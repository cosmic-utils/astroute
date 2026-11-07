use crate::{
    Result, inventory,
    kernel::{self, Kernel},
    linux,
    proxy::{Relay, Settings},
    scopes,
    types::{Entry, Fallback, Mode, Policy, Profile, valid_id},
};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::MetadataExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: i32) {
    STOP.store(true, Ordering::Relaxed);
}
#[derive(PartialEq, Eq)]
struct Signature {
    profile: Profile,
    interface: Option<String>,
    interface_index: Option<u32>,
    mode: Mode,
    fallback: Fallback,
}
struct ActiveRelay {
    signature: Signature,
    group: PathBuf,
    worker: Relay,
}
struct Agent {
    uid: u32,
    policies: BTreeMap<String, Policy>,
    proxies: BTreeMap<String, Profile>,
    relays: BTreeMap<String, ActiveRelay>,
    groups: BTreeMap<PathBuf, String>,
    bound: BTreeMap<PathBuf, (Option<String>, Option<u32>)>,
    interfaces: BTreeMap<String, Option<u32>>,
    children: BTreeMap<u32, String>,
    events: VecDeque<Value>,
    running: bool,
    disabling: bool,
    kernel: Kernel,
}
impl Agent {
    fn new(uid: u32) -> Result<Self> {
        ensure!(uid > 0, "The network agent must target a non-root user");
        let mut agent = Self {
            uid,
            policies: BTreeMap::new(),
            proxies: BTreeMap::new(),
            relays: BTreeMap::new(),
            groups: BTreeMap::new(),
            bound: BTreeMap::new(),
            interfaces: BTreeMap::new(),
            children: BTreeMap::new(),
            events: VecDeque::new(),
            running: true,
            disabling: false,
            kernel: Kernel::new(uid)?,
        };
        agent.event("Network controls enabled");
        Ok(agent)
    }
    fn event(&mut self, text: impl Into<String>) {
        let mut now = 0;
        unsafe {
            libc::time(&mut now);
        }
        let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
        let time = if unsafe { libc::localtime_r(&now, tm.as_mut_ptr()) }.is_null() {
            "00:00:00".into()
        } else {
            let tm = unsafe { tm.assume_init() };
            format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
        };
        self.events
            .push_front(json!({"time":time,"text":text.into()}));
        self.events.truncate(150);
    }
    fn interface_available(&self, policy: &Policy) -> bool {
        policy
            .interface
            .as_ref()
            .is_none_or(|i| self.interfaces.get(i).is_some_and(Option::is_some))
    }
    fn entries(&self) -> Vec<Entry> {
        self.groups
            .iter()
            .filter(|(path, _)| path.exists())
            .filter_map(|(path, id)| {
                let mut policy = self.policies.get(id)?.clone();
                if !self.interface_available(&policy) {
                    policy.mode = Mode::Block;
                    policy.proxy = None;
                }
                let relay = self.relays.get(id);
                Some(Entry {
                    policy,
                    cgroup: path
                        .strip_prefix("/sys/fs/cgroup")
                        .ok()?
                        .to_string_lossy()
                        .into(),
                    proxy_port: relay.map(|r| r.worker.port),
                    dns_port: relay.map(|r| r.worker.dns_port),
                })
            })
            .collect()
    }
    fn rebuild(&mut self, held: &[Entry]) -> Result<()> {
        let entries = self.entries();
        let mut closed = BTreeMap::new();
        for e in held.iter().chain(entries.iter()) {
            if Path::new("/sys/fs/cgroup").join(&e.cgroup).exists() {
                let mut e = e.clone();
                e.policy.mode = Mode::Block;
                e.policy.proxy = None;
                closed.insert(e.cgroup.clone(), e);
            }
        }
        self.kernel
            .apply(&closed.into_values().collect::<Vec<_>>())?;
        let needed: BTreeSet<_> = self
            .groups
            .values()
            .filter(|id| {
                self.policies.get(*id).is_some_and(|p| {
                    p.proxy.is_some() && p.mode != Mode::Block && self.interface_available(p)
                })
            })
            .cloned()
            .collect();
        let mut remove = Vec::new();
        for (id, relay) in &mut self.relays {
            let signature = self.policies.get(id).and_then(|p| {
                p.proxy
                    .as_ref()
                    .and_then(|key| self.proxies.get(key))
                    .map(|profile| Signature {
                        profile: profile.clone(),
                        interface: p.interface.clone(),
                        interface_index: p
                            .interface
                            .as_ref()
                            .and_then(|i| self.interfaces.get(i).copied().flatten()),
                        mode: p.mode,
                        fallback: p.proxy_fallback,
                    })
            });
            if !needed.contains(id)
                || signature.as_ref() != Some(&relay.signature)
                || relay.worker.ended()
            {
                remove.push(id.clone());
            }
        }
        for id in remove {
            self.stop_relay(&id);
        }
        for id in needed {
            if self.relays.contains_key(&id) {
                continue;
            }
            let policy = &self.policies[&id];
            let profile = self
                .proxies
                .get(policy.proxy.as_ref().unwrap())
                .context("The selected proxy profile is unavailable")?
                .clone();
            let signature = Signature {
                profile: profile.clone(),
                interface: policy.interface.clone(),
                interface_index: policy
                    .interface
                    .as_ref()
                    .and_then(|i| self.interfaces.get(i).copied().flatten()),
                mode: policy.mode,
                fallback: policy.proxy_fallback,
            };
            let group = self
                .kernel
                .group(&format!("relay-{}", &kernel::group_key(&id)[4..]))?;
            let result = (|| -> Result<Relay> {
                self.kernel.bind(&group, policy.interface.as_deref())?;
                Relay::start(
                    self.uid,
                    &group,
                    &Settings {
                        profile,
                        mode: policy.mode,
                        fallback: policy.proxy_fallback,
                    },
                )
            })();
            match result {
                Ok(worker) => {
                    self.relays.insert(
                        id,
                        ActiveRelay {
                            signature,
                            group,
                            worker,
                        },
                    );
                }
                Err(error) => {
                    self.release_relay_group(&group);
                    return Err(error);
                }
            }
        }
        for (path, id) in &self.groups {
            if !path.exists() {
                continue;
            }
            let policy = self.policies.get(id);
            if policy.is_some_and(|p| !self.interface_available(p)) {
                self.kernel.unbind(path);
                self.bound.remove(path);
                continue;
            }
            let interface = if policy.is_some_and(|p| p.proxy.is_some()) {
                Some("lo".into())
            } else {
                policy.and_then(|p| p.interface.clone())
            };
            let binding = (
                interface.clone(),
                interface.as_deref().and_then(|i| linux::ifindex(i).ok()),
            );
            if self.bound.get(path) != Some(&binding) {
                self.kernel.bind(path, interface.as_deref())?;
                self.bound.insert(path.clone(), binding);
            }
        }
        let mut entries = self.entries();
        for (id, relay) in &self.relays {
            entries.push(Entry {
                policy: Policy {
                    app_id: id.clone(),
                    mode: Mode::Allow,
                    interface: self.policies[id].interface.clone(),
                    proxy: None,
                    proxy_fallback: Fallback::Block,
                },
                cgroup: relay
                    .group
                    .strip_prefix("/sys/fs/cgroup")?
                    .to_string_lossy()
                    .into(),
                proxy_port: None,
                dns_port: None,
            });
        }
        self.kernel.refresh_routes()?;
        self.kernel.apply(&entries)
    }
    fn release_relay_group(&mut self, path: &Path) {
        self.kernel.unbind(path);
        let _ = fs::remove_dir(path);
    }
    fn stop_relay(&mut self, id: &str) {
        if let Some(relay) = self.relays.remove(id) {
            let group = relay.group.clone();
            drop(relay);
            self.release_relay_group(&group);
        }
    }
    fn reconcile(&mut self) -> Result<bool> {
        let catalog = inventory::applications(self.uid, true)?;
        let saved = self.policies.keys().cloned().collect();
        let interfaces: BTreeMap<_, _> = self
            .policies
            .values()
            .filter_map(|p| p.interface.as_ref())
            .map(|i| (i.clone(), linux::ifindex(i).ok()))
            .collect();
        let mut changed = interfaces != self.interfaces;
        if changed {
            self.kernel.invalidate_routes();
        }
        self.interfaces = interfaces;
        for (path, id) in
            scopes::discover(self.uid, &catalog, &saved, &inventory::processes(self.uid))
        {
            let path = PathBuf::from(format!("/sys/fs/cgroup{path}"));
            if self.groups.get(&path) != Some(&id) {
                self.groups.insert(path, id);
                changed = true;
            }
        }
        let remove: Vec<_> = self
            .groups
            .keys()
            .filter(|p| {
                fs::read_to_string(p.join("cgroup.events"))
                    .map(|s| s.contains("populated 0"))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        for path in remove {
            self.kernel.unbind(&path);
            self.groups.remove(&path);
            self.bound.remove(&path);
            if path.parent() == Some(&self.kernel.root) {
                let _ = fs::remove_dir(path);
            }
            changed = true;
        }
        let mut ended = Vec::new();
        for (&pid, name) in &self.children {
            let mut status = 0;
            let result = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
            if result > 0
                || (result < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
            {
                ended.push((pid, name.clone(), status));
            }
        }
        for (pid, name, status) in ended {
            self.children.remove(&pid);
            let status = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -libc::WTERMSIG(status)
            };
            self.event(format!("{name} exited ({status})"));
        }
        if self.relays.values_mut().any(|r| r.worker.ended()) {
            changed = true;
        }
        Ok(changed)
    }
    fn replace(
        &mut self,
        policies: BTreeMap<String, Policy>,
        profiles: BTreeMap<String, Profile>,
    ) -> Result<()> {
        let held = self.entries();
        let old_policies = std::mem::replace(&mut self.policies, policies);
        let old_profiles = std::mem::replace(&mut self.proxies, profiles);
        let result = (|| -> Result<()> {
            self.reconcile()?;
            self.rebuild(&held)
        })();
        if let Err(error) = result {
            self.policies = old_policies;
            self.proxies = old_profiles;
            self.rebuild(&[])
                .context("Unable to restore previous controls")?;
            return Err(error);
        }
        Ok(())
    }
    fn sync(&mut self, request: &Value) -> Result<Value> {
        let raw_rules = request["policies"]
            .as_array()
            .filter(|v| v.len() <= 1000)
            .context("Invalid saved rules")?;
        let raw_profiles = request["profiles"]
            .as_array()
            .filter(|v| v.len() <= 100)
            .context("Invalid proxy profiles")?;
        let mut profiles = BTreeMap::new();
        let mut policies = BTreeMap::new();
        for raw in raw_profiles {
            let p = Profile::parse(raw, None)?;
            ensure!(
                profiles.insert(p.id.clone(), p).is_none(),
                "Duplicate proxy ID"
            );
        }
        let catalog = inventory::applications(self.uid, false)?;
        for raw in raw_rules {
            let p = Policy::parse(raw)?;
            ensure!(
                catalog.iter().any(|a| a.id == p.app_id && a.controllable),
                "Application cannot be controlled: {}",
                p.app_id
            );
            ensure!(
                p.proxy.as_ref().is_none_or(|id| profiles.contains_key(id)),
                "The selected proxy profile is unavailable"
            );
            ensure!(
                policies.insert(p.app_id.clone(), p).is_none(),
                "Duplicate application rule"
            );
        }
        self.replace(policies, profiles)?;
        self.event("Saved application rules applied");
        Ok(
            json!({"message":"Saved rules applied. Relaunch apps to apply routing to every connection."}),
        )
    }
    fn launch(&mut self, id: &str, request: &Value) -> Result<Value> {
        ensure!(valid_id(id, 241), "Invalid application ID");
        let user = linux::user(self.uid)?;
        let app = inventory::applications(self.uid, false)?
            .into_iter()
            .find(|a| a.id == id)
            .context("Application is not installed")?;
        ensure!(app.controllable, "{}", app.reason);
        let inputs: Vec<String> =
            serde_json::from_value(request.get("inputs").cloned().unwrap_or(json!([])))?;
        let argv = inventory::desktop_argv_with_inputs(
            &inventory::desktop_section(&linux::read_limited(Path::new(&app.path), 1024 * 1024)?),
            Path::new(&app.path),
            &inputs,
        )?;
        let name = app.name;
        let directory = if app.working_dir.is_empty() {
            user.home.clone()
        } else {
            PathBuf::from(app.working_dir)
        };
        let policy = self
            .policies
            .get(id)
            .context("No applied rule for this application; apply saved rules before launching")?
            .clone();
        let environment = launch_environment(
            self.uid,
            &request["environment"],
            policy.interface.as_deref(),
        )?;
        let group = self.kernel.group(&kernel::group_key(id))?;
        let held = self.entries();
        let (pid, mut gate) = linux::spawn_gated(&user, &group, &argv, &environment, &directory)?;
        let result = (|| -> Result<()> {
            fs::write(group.join("cgroup.procs"), pid.to_string())?;
            self.groups.insert(group.clone(), id.into());
            self.rebuild(&held)?;
            gate.write_all(b"1")?;
            Ok(())
        })();
        if let Err(error) = result {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
                libc::waitpid(pid as i32, std::ptr::null_mut(), 0);
            }
            self.rebuild(&[])?;
            return Err(error);
        }
        self.children.insert(pid, name.clone());
        self.event(format!("Launched {name} with network controls"));
        Ok(json!({"pid":pid,"message":format!("Launched {name}")}))
    }
    fn snapshot(&self) -> Result<Value> {
        let mut state = inventory::snapshot(self.uid)?;
        state["enabled"] = json!(true);
        state["message"] = json!("Network controls are active");
        state["policies"] = serde_json::to_value(self.policies.values().collect::<Vec<_>>())?;
        state["events"] = json!(self.events);
        state["proxies"] = json!(
            self.proxies
                .values()
                .map(Profile::public)
                .collect::<Vec<_>>()
        );
        state["active"] = json!(
            self.groups
                .iter()
                .map(|(path, id)| {
                    let pids: Vec<u32> = fs::read_to_string(path.join("cgroup.procs"))
                        .unwrap_or_default()
                        .split_whitespace()
                        .filter_map(|p| p.parse().ok())
                        .collect();
                    json!({"app_id":id,"pids":pids,"cgroup":path, "interface_unavailable":self.policies.get(id).is_some_and(|p| !self.interface_available(p))})
                })
                .collect::<Vec<_>>()
        );
        Ok(state)
    }
    fn shutdown(&mut self) -> Result<()> {
        for id in self.relays.keys().cloned().collect::<Vec<_>>() {
            self.stop_relay(&id);
        }
        self.kernel.shutdown()
    }
    fn dispatch(&mut self, request: &Value) -> Result<Value> {
        let method = request["method"].as_str().unwrap_or("");
        ensure!(
            !self.disabling || matches!(method, "disable" | "snapshot"),
            "Controls are shutting down. Retry disabling controls to finish cleanup."
        );
        match method {
            "snapshot" => self.snapshot(),
            "sync-policies" => self.sync(request),
            "launch" => self.launch(request["app_id"].as_str().unwrap_or(""), request),
            "disable" => {
                self.disabling = true;
                self.shutdown()?;
                self.running = false;
                Ok(
                    json!({"message":"Network controls disabled", "enabled":false, "shutdown_complete":true}),
                )
            }
            _ => bail!("Unknown request"),
        }
    }
}
impl Drop for Agent {
    fn drop(&mut self) {
        let ids: Vec<_> = self.relays.keys().cloned().collect();
        for id in ids {
            self.stop_relay(&id);
        }
    }
}
pub fn launch_environment(
    uid: u32,
    supplied: &Value,
    interface: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let user = linux::user(uid)?;
    let name = user.name.to_string_lossy().into_owned();
    let mut result = BTreeMap::from([
        ("HOME".into(), user.home.to_string_lossy().into_owned()),
        ("USER".into(), name.clone()),
        ("LOGNAME".into(), name),
        ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
        ("XDG_RUNTIME_DIR".into(), format!("/run/user/{uid}")),
        (
            "DBUS_SESSION_BUS_ADDRESS".into(),
            format!("unix:path=/run/user/{uid}/bus"),
        ),
    ]);
    let allowed = [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_TYPE",
        "DESKTOP_SESSION",
        "LANG",
        "LANGUAGE",
        "XDG_DATA_DIRS",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "GTK_THEME",
        "QT_QPA_PLATFORM",
        "GDK_BACKEND",
    ];
    if let Some(supplied) = supplied.as_object() {
        for (key, value) in supplied {
            if (allowed.contains(&key.as_str()) || key.starts_with("LC_"))
                && let Some(text) = value
                    .as_str()
                    .filter(|s| s.len() < 4096 && !s.contains('\0'))
            {
                result.insert(key.clone(), text.into());
            }
        }
    }
    if let Some(index) = interface.and_then(|i| linux::ifindex(i).ok()) {
        result.insert("SYSTEMD_NSS_RESOLVE_IFINDEX".into(), index.to_string());
    }
    Ok(result)
}
pub fn read_message(stream: &mut impl Read, limit: usize) -> Result<Value> {
    let mut reader = BufReader::new(stream.take(limit as u64 + 1));
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line)?;
    ensure!(line.len() <= limit, "Message is too large");
    ensure!(line.last() == Some(&b'\n'), "Incomplete message");
    Ok(serde_json::from_slice(&line)?)
}
fn authorized(stream: &UnixStream, uid: u32) -> bool {
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            peer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    result == 0
        && size as usize == std::mem::size_of::<libc::ucred>()
        && unsafe { peer.assume_init() }.uid == uid
}
struct SocketFile(PathBuf);
impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn runtime(uid: u32) -> Result<(linux::User, PathBuf, fs::File)> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Network controls require administrator authentication"
    );
    ensure!(uid > 0, "Refusing to manage root applications");
    let user = linux::user(uid)?;
    unsafe {
        libc::umask(0o077);
    }
    let runtime = PathBuf::from("/run/cosmic-netguard");
    let base = runtime.join(uid.to_string());
    for directory in [&runtime, &base] {
        fs::create_dir_all(directory)?;
        let metadata = fs::symlink_metadata(directory)?;
        ensure!(
            metadata.is_dir() && metadata.uid() == 0,
            "Invalid helper runtime directory"
        );
        linux::mode(directory, 0o755)?;
    }
    let lock = match linux::lock(&base.join("agent.lock"), true) {
        Ok(lock) => lock,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) =>
        {
            bail!("The network helper is already running; retry disabling controls");
        }
        Err(error) => return Err(error),
    };
    Ok((user, base, lock))
}

/// Recover only resources recorded in the root-owned runtime directory.
pub fn cleanup(uid: u32) -> Result<()> {
    let (_, base, _lock) = runtime(uid)?;
    Kernel::new(uid)?.shutdown()?;
    for name in ["active", "control.sock"] {
        match fs::remove_file(base.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn serve(uid: u32) -> Result<()> {
    let (user, base, _lock) = runtime(uid)?;
    // Record cleanup responsibility before touching persistent kernel resources.
    let active = base.join("active");
    linux::atomic_write(&active, b"Astroute network controls\n", 0o644)?;
    Kernel::new(uid)?.shutdown()?;
    let socket = base.join("control.sock");
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    let _socket = SocketFile(socket.clone());
    let mut agent = Agent::new(uid)?;
    let listener = UnixListener::bind(&socket)?;
    let path = std::ffi::CString::new(socket.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(path.as_ptr(), uid, user.gid) } == 0,
        "Unable to set helper socket owner"
    );
    linux::mode(&socket, 0o600)?;
    listener.set_nonblocking(true)?;
    STOP.store(false, Ordering::Relaxed);
    unsafe {
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let mut routes = Instant::now() - Duration::from_secs(6);
    while agent.running && !STOP.load(Ordering::Relaxed) {
        if !agent.disabling {
            match agent.reconcile() {
                Ok(true) => {
                    if let Err(error) = agent.rebuild(&[]) {
                        agent.event(format!("Control update: {error}"));
                    }
                }
                Ok(false) => {}
                Err(error) => agent.event(format!("Application discovery: {error}")),
            }
            if routes.elapsed() > Duration::from_secs(5) {
                if let Err(error) = agent.kernel.refresh_routes() {
                    agent.event(format!("Route refresh: {error}"));
                }
                routes = Instant::now();
            }
        }
        if !linux::poll(listener.as_raw_fd(), 1000)? {
            continue;
        }
        let (mut stream, _) = match listener.accept() {
            Ok(client) => client,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error.into()),
        };
        if !authorized(&stream, uid) {
            continue;
        }
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let result = read_message(&mut stream, 1024 * 1024).and_then(|request| {
            ensure!(request.is_object(), "Expected an object");
            agent.dispatch(&request)
        });
        let response = match result {
            Ok(data) => json!({"ok":true,"data":data}),
            Err(error) => {
                let message = error.to_string();
                agent.event(message.clone());
                json!({"ok":false,"error":message})
            }
        };
        if let Ok(mut bytes) = serde_json::to_vec(&response) {
            bytes.push(b'\n');
            let _ = stream.write_all(&bytes);
        }
    }
    agent.shutdown()?;
    fs::remove_file(active)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipc_rejects_other_users_incomplete_and_oversized_messages() {
        let (stream, _) = UnixStream::pair().unwrap();
        assert!(authorized(&stream, linux::uid()));
        assert!(!authorized(&stream, linux::uid().wrapping_add(1)));
        assert!(read_message(&mut b"{}".as_slice(), 1024).is_err());
        assert!(read_message(&mut b"{\"method\":\"snapshot\"}\n".as_slice(), 4).is_err());
        assert_eq!(
            read_message(&mut b"{\"method\":\"snapshot\"}\n".as_slice(), 1024).unwrap()["method"],
            "snapshot"
        );
    }
}
