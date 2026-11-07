use crate::{
    Result, daemon, inventory, launcher, linux, proxy,
    store::Store,
    types::{Application, Policy, Profile},
};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{fs::OpenOptionsExt, net::UnixStream, process::CommandExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn request(data: &Value) -> Result<Value> {
    request_at(&runtime_path("control.sock"), data)
}
fn request_at(path: &std::path::Path, data: &Value) -> Result<Value> {
    let mut payload = serde_json::to_vec(data)?;
    payload.push(b'\n');
    ensure!(
        payload.len() <= 1024 * 1024,
        "Network agent request is too large"
    );
    let connected = UnixStream::connect(path);
    let mut stream = match connected {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => bail!(
            "Cannot access the network helper. Enable controls again to repair its runtime directory."
        ),
        other => other?,
    };
    stream.set_read_timeout(Some(Duration::from_secs(if data["method"] == "disable" {
        90
    } else {
        15
    })))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    stream.write_all(&payload)?;
    let reply = daemon::read_message(&mut stream, 8 * 1024 * 1024)?;
    ensure!(
        reply["ok"] == true,
        "{}",
        reply["error"].as_str().unwrap_or("Network agent failed")
    );
    Ok(reply["data"].clone())
}
fn absent(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|e| {
        matches!(
            e.kind(),
            std::io::ErrorKind::NotFound
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
        )
    })
}
fn agent_state() -> Result<Option<Value>> {
    match request(&json!({"method":"snapshot"})) {
        Ok(state) => Ok(Some(state)),
        Err(error) if absent(&error) => Ok(None),
        Err(error) => Err(error),
    }
}
fn apps(state: &Value) -> Result<Vec<Application>> {
    Ok(serde_json::from_value(
        state.get("apps").cloned().unwrap_or(json!([])),
    )?)
}
fn runtime_path(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/run/cosmic-netguard/{}/{name}", linux::uid()))
}
fn needs_cleanup() -> bool {
    runtime_path("active").exists() || runtime_path("control.sock").exists()
}
fn pending_rules(
    state: &Value,
    catalog: &[Application],
    saved: &BTreeMap<String, crate::types::Rule>,
    profiles: &BTreeMap<String, Profile>,
) -> Result<BTreeSet<String>> {
    let applied: BTreeMap<String, Policy> = state["policies"]
        .as_array()
        .into_iter()
        .flatten()
        .map(Policy::parse)
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(|p| (p.app_id.clone(), p))
        .collect();
    let mut pending = BTreeSet::new();
    for (id, rule) in saved {
        let proxy_changed = rule.policy.proxy.as_ref().is_some_and(|proxy| {
            let revision = profiles.get(proxy).map(|p| p.revision.as_str());
            !state["proxies"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|p| p["id"] == *proxy && p["revision"].as_str() == revision)
        });
        if catalog.iter().any(|a| a.id == *id && a.controllable)
            && (state["enabled"] != true
                || applied.get(id) != Some(&rule.policy)
                || !catalog.iter().any(|a| a.id == *id && a.managed_launcher)
                || proxy_changed)
        {
            pending.insert(id.clone());
        }
    }
    pending.extend(
        applied
            .keys()
            .filter(|id| !saved.contains_key(*id))
            .cloned(),
    );
    Ok(pending)
}
fn snapshot() -> Result<Value> {
    let mut state = match agent_state()? {
        Some(state) => state,
        None => {
            ensure!(
                !needs_cleanup(),
                "The network helper stopped unexpectedly. Disable controls to clean up, or enable controls to recover."
            );
            inventory::snapshot(linux::uid())?
        }
    };
    let store = Store::user()?;
    let catalog = apps(&state)?;
    let saved = store.rules()?;
    let profiles = store.profiles()?;
    state["pending_rules"] = json!(pending_rules(&state, &catalog, &saved, &profiles)?);
    state["policies"] = serde_json::to_value(saved.values().collect::<Vec<_>>())?;
    state["proxies"] = json!(profiles.values().map(Profile::public).collect::<Vec<_>>());
    Ok(state)
}
fn apply_saved(state: &Value) -> Result<Value> {
    let store = Store::user()?;
    let saved = store.rules()?;
    let catalog = apps(state)?;
    let policies: Vec<_> = saved
        .values()
        .filter(|r| {
            catalog
                .iter()
                .any(|a| a.id == r.policy.app_id && a.controllable)
        })
        .map(|r| r.policy.clone())
        .collect();
    let ids: BTreeSet<_> = policies.iter().filter_map(|p| p.proxy.as_deref()).collect();
    let mut profiles = BTreeMap::new();
    for id in ids {
        profiles.insert(id, store.profile(id)?);
    }
    // Install launch gates before publishing the policies. Launch requests queue
    // behind sync on the helper, so applications cannot exec before enforcement.
    for app in &catalog {
        if saved.contains_key(&app.id) && app.controllable {
            launcher::set(&app.id, true)?;
        }
    }
    let result = request(
        &json!({"method":"sync-policies", "policies":policies, "profiles":profiles.values().collect::<Vec<_>>()}),
    )?;
    for app in catalog {
        let controlled = saved.contains_key(&app.id) && app.controllable;
        if controlled != app.managed_launcher {
            launcher::set(&app.id, controlled).with_context(|| {
                format!(
                    "Rules were applied, but the launcher for {} could not be updated",
                    app.id
                )
            })?;
        }
    }
    Ok(result)
}
fn enable() -> Result<Value> {
    if let Some(state) = agent_state()? {
        return apply_saved(&state);
    }
    let (_, directory) = inventory::user_paths(linux::uid())?;
    fs::create_dir_all(&directory)?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("helper.log"))?;
    let mut command = Command::new("/usr/bin/pkexec");
    command
        .arg(linux::helper_path()?)
        .arg("--uid")
        .arg(linux::uid().to_string())
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = command.spawn()?;
    for _ in 0..240 {
        match agent_state() {
            Ok(Some(state)) => return apply_saved(&state),
            _ => {
                if let Some(status) = child.try_wait()? {
                    bail!(
                        "Network helper exited during startup (status {status}). See ~/.local/state/cosmic-netguard/helper.log for details."
                    );
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
    bail!("Authentication timed out")
}
fn disable() -> Result<Value> {
    let stopping = match request(&json!({"method":"disable"})) {
        Ok(_) => true,
        Err(error) if absent(&error) => {
            if needs_cleanup() {
                let status = Command::new("/usr/bin/pkexec")
                    .arg(linux::helper_path()?)
                    .args(["--cleanup", "--uid", &linux::uid().to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .status()?;
                ensure!(
                    status.success() && !needs_cleanup(),
                    "Network cleanup failed or authentication was cancelled; Astroute will stay open"
                );
            }
            false
        }
        Err(error) => return Err(error),
    };
    let socket = std::path::PathBuf::from(format!(
        "/run/cosmic-netguard/{}/control.sock",
        linux::uid()
    ));
    let deadline = Instant::now() + Duration::from_secs(90);
    while stopping && (socket.exists() || runtime_path("active").exists()) {
        ensure!(
            Instant::now() < deadline,
            "The network helper is still shutting down; Astroute will stay open"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    launcher::restore_all()?;
    Ok(json!({"message":"Network controls disabled", "enabled":false}))
}

fn launch_direct(id: &str, inputs: &[String]) -> Result<Value> {
    ensure!(
        linux::uid() > 0,
        "Refusing to launch a desktop application as root"
    );
    let app = inventory::applications(linux::uid(), false)?
        .into_iter()
        .find(|app| app.id == id)
        .context("Application is not installed")?;
    let argv = inventory::desktop_argv_with_inputs(
        &inventory::desktop_section(&linux::read_limited(
            std::path::Path::new(&app.path),
            1024 * 1024,
        )?),
        std::path::Path::new(&app.path),
        inputs,
    )?;
    let executable = &argv[0];
    let mut command = Command::new(executable);
    command
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !app.working_dir.is_empty() {
        command.current_dir(&app.working_dir);
    }
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let child = command.spawn().context("Unable to launch application")?;
    Ok(
        json!({"message":"Application launched without network controls", "pid":child.id(), "enabled":false}),
    )
}

fn argument(arguments: &[String], index: usize) -> Result<&str> {
    arguments
        .get(index)
        .map(String::as_str)
        .context("Missing command argument")
}
pub fn run(arguments: &[String]) -> Result<Value> {
    let method = arguments.first().map(String::as_str).unwrap_or("snapshot");
    match method {
        "snapshot" => snapshot(),
        "enable" => enable().map(|mut value| {
            value["enabled"] = json!(true);
            value
        }),
        "apply" => apply_saved(&agent_state()?.context("Enable controls to apply saved rules")?),
        "test-proxy" => {
            ensure!(arguments.len() == 2, "Select a saved proxy to test");
            proxy::runtime()?.block_on(proxy::probe(&Store::user()?.profile(&arguments[1])?))
        }
        "save" | "save-proxy" => {
            ensure!(
                method != "save-proxy" || arguments.len() == 1,
                "Proxy profiles must be supplied through standard input"
            );
            let raw = if let Some(raw) = arguments.get(1) {
                raw.clone()
            } else {
                let mut raw = String::new();
                std::io::stdin().take(65537).read_to_string(&mut raw)?;
                ensure!(raw.len() <= 65536, "Settings are too large");
                raw
            };
            let value: Value = serde_json::from_str(&raw)?;
            let store = Store::user()?;
            if method == "save-proxy" {
                return Ok(json!({"profile":store.save_profile(&value)?.public()}));
            }
            if let Some(id) = value["proxy"].as_str().filter(|s| !s.is_empty()) {
                store.profile(id)?;
            }
            store.save_rule(&value)?;
            (|| -> Result<Value> {
                match agent_state()? {
                    Some(state) => apply_saved(&state),
                    None => Ok(json!({"message":"Rule saved. Enable controls to apply it."})),
                }
            })()
            .context("Rule saved locally, but could not be fully applied")
        }
        "remove-proxy" => {
            let id = argument(arguments, 1)?;
            let store = Store::user()?;
            ensure!(
                !store
                    .rules()?
                    .values()
                    .any(|r| r.policy.proxy.as_deref() == Some(id)),
                "Remove this proxy from application rules before deleting it"
            );
            store.remove("proxies", id)?;
            Ok(json!({"message":"Proxy profile removed from your settings"}))
        }
        "remove" => {
            let id = argument(arguments, 1)?;
            Store::user()?.remove("rules", id)?;
            (|| -> Result<Value>{if let Some(state)=agent_state()?{apply_saved(&state)}else{launcher::set(id,false)?;Ok(json!({"message":"Rule removed"}))}})().context("Rule removed from saved settings, but active controls or its launcher could not be updated")
        }
        "launch" => {
            let id = argument(arguments, 1)?;
            let inputs = arguments.get(2..).unwrap_or_default();
            let inputs = inputs.strip_prefix(&["--".to_owned()]).unwrap_or(inputs);
            let Some(state) = agent_state()? else {
                ensure!(
                    !needs_cleanup(),
                    "The network helper stopped unexpectedly. Recover or disable controls before launching this application."
                );
                return launch_direct(id, inputs);
            };
            apply_saved(&state)?;
            let message = json!({"method":"launch","app_id":id,"inputs":inputs,"environment":std::env::vars().collect::<BTreeMap<_,_>>()});
            request(&message)
        }
        "disable" => disable(),
        _ => bail!("Unknown command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Rule;
    use std::os::unix::net::UnixListener;

    fn catalog() -> Vec<Application> {
        vec![serde_json::from_value(json!({"id":"browser", "name":"Browser", "icon":"browser", "argv":["browser"], "path":"/browser.desktop", "working_dir":"/tmp", "controllable":true, "reason":"", "managed_launcher":true})).unwrap()]
    }
    #[test]
    fn password_only_edits_remain_pending_until_the_new_revision_is_applied() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store {
            directory: temporary.path().join("settings"),
        };
        let raw = json!({"id":"office", "name":"Office", "protocol":"http", "host":"proxy.example", "port":8080, "username":"user", "password":"first"});
        let first = store.save_profile(&raw).unwrap();
        let rule = Rule::parse(&json!({"app_id":"browser", "proxy":"office"})).unwrap();
        let saved = BTreeMap::from([("browser".into(), rule.clone())]);
        let mut state =
            json!({"enabled":true, "policies":[rule.policy], "proxies":[first.public()]});
        assert!(
            pending_rules(&state, &catalog(), &saved, &store.profiles().unwrap())
                .unwrap()
                .is_empty()
        );
        let mut edit = raw;
        edit["password"] = json!("second");
        let second = store.save_profile(&edit).unwrap();
        assert_eq!(
            pending_rules(&state, &catalog(), &saved, &store.profiles().unwrap()).unwrap(),
            BTreeSet::from(["browser".into()])
        );
        state["proxies"] = json!([second.public()]);
        assert!(
            pending_rules(&state, &catalog(), &saved, &store.profiles().unwrap())
                .unwrap()
                .is_empty()
        );
        assert!(!state.to_string().contains("second"));
        let mut apps = catalog();
        apps[0].managed_launcher = false;
        assert!(
            pending_rules(&state, &apps, &saved, &store.profiles().unwrap())
                .unwrap()
                .contains("browser")
        );
    }
    #[test]
    fn ipc_shutdown_errors_and_disconnects_cannot_acknowledge_cleanup() {
        let temporary = tempfile::tempdir().unwrap();
        for reply in [
            b"{\"ok\":false,\"error\":\"cleanup failed\"}\n".as_slice(),
            b"{\"ok\":true".as_slice(),
        ] {
            let path = temporary.path().join("helper.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let reply = reply.to_vec();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let request = daemon::read_message(&mut stream, 1024).unwrap();
                assert_eq!(request["method"], "disable");
                stream.write_all(&reply).unwrap();
            });
            let error = request_at(&path, &json!({"method":"disable"})).unwrap_err();
            assert!(!absent(&error));
            server.join().unwrap();
            fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn ipc_validates_request_size_before_connecting() {
        let temporary = tempfile::tempdir().unwrap();
        let error = request_at(
            &temporary.path().join("missing"),
            &json!({"method":"launch", "inputs":["x".repeat(1024 * 1024)]}),
        )
        .unwrap_err();
        assert!(error.to_string().contains("too large"));
    }
}
