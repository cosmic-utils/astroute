//! Manual harness. Run only inside a new network namespace; never invoked by cargo test.
use anyhow::{Context, Result, bail, ensure};
use astroute_backend::{
    inventory,
    kernel::Kernel,
    launcher::desktop_quote,
    linux, proxy,
    types::{Entry, Fallback, Mode, Policy},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

struct Background(Child);
impl Drop for Background {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn background(command: &mut Command) -> Result<Background> {
    let mut child = Background(command.stdout(Stdio::piped()).spawn()?);
    let pipe = child.0.stdout.as_mut().context("Missing readiness pipe")?;
    ensure!(
        linux::poll(pipe.as_raw_fd(), 5000)?,
        "Background process startup timed out"
    );
    let mut line = String::new();
    BufReader::new(pipe).read_line(&mut line)?;
    ensure!(line.trim() == "READY", "Background process failed: {line}");
    Ok(child)
}
fn ip(arguments: &[&str]) -> Result<()> {
    let mut argv = linux::args(&["/usr/bin/ip"]);
    argv.extend(linux::args(arguments));
    linux::command(&argv, None, true)?;
    Ok(())
}
fn peer(pid: u32, arguments: &[&str]) -> Result<()> {
    let mut argv = linux::args(&[
        "/usr/bin/nsenter",
        "-t",
        &pid.to_string(),
        "-n",
        "/usr/bin/ip",
    ]);
    argv.extend(linux::args(arguments));
    linux::command(&argv, None, true)?;
    Ok(())
}
fn address(host: &str) -> Result<SocketAddr> {
    Ok(SocketAddr::new(host.parse()?, 18764))
}
fn connect(host: &str, transport: &str, output: &Path) -> Result<()> {
    let target = address(host)?;
    let mut mark = 0u32;
    let mut mark_len = 4u32;
    let result = (|| -> Result<String> {
        let mut bytes = [0u8; 256];
        let count = if transport == "udp" {
            let bind = if target.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let socket = UdpSocket::bind(bind)?;
            socket.set_read_timeout(Some(Duration::from_millis(1500)))?;
            socket.connect(target)?;
            unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&mut mark as *mut u32).cast(),
                    &mut mark_len,
                );
            }
            socket.send(b"probe")?;
            socket.recv(&mut bytes)?
        } else {
            let mut socket = TcpStream::connect_timeout(&target, Duration::from_millis(1500))?;
            socket.set_read_timeout(Some(Duration::from_millis(1500)))?;
            unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&mut mark as *mut u32).cast(),
                    &mut mark_len,
                );
            }
            socket.read(&mut bytes)?
        };
        Ok(std::str::from_utf8(&bytes[..count])?.into())
    })();
    let failed = result.is_err();
    let (source, error) = match result {
        Ok(source) => (Some(source), None),
        Err(error) => (None, Some(error.to_string())),
    };
    let value = json!({"uid":linux::uid(),"euid":unsafe{libc::geteuid()},"mark":mark,"source":source,"error":error,"cgroup":fs::read_to_string("/proc/self/cgroup")?});
    fs::write(output, serde_json::to_vec(&value)?)?;
    if failed {
        std::process::exit(7);
    }
    Ok(())
}
fn echo_server() -> Result<()> {
    for host in ["10.203.0.1", "2001:db8:3::1"] {
        let listener = std::net::TcpListener::bind(address(host)?)?;
        std::thread::spawn(move || {
            for (mut stream, peer) in listener.incoming().filter_map(|s| s.ok()).filter_map(|s| {
                let p = s.peer_addr().ok()?;
                Some((s, p))
            }) {
                let _ = stream.write_all(peer.ip().to_string().as_bytes());
            }
        });
        let socket = UdpSocket::bind(address(host)?)?;
        std::thread::spawn(move || {
            let mut bytes = [0u8; 256];
            while let Ok((_, peer)) = socket.recv_from(&mut bytes) {
                let _ = socket.send_to(peer.ip().to_string().as_bytes(), peer);
            }
        });
    }
    println!("READY");
    std::io::stdout().flush()?;
    loop {
        std::thread::park();
    }
}
async fn proxy_connection(
    mut stream: tokio::net::TcpStream,
    socks: bool,
    log: Arc<PathBuf>,
) -> Result<()> {
    let (host, port) = if socks {
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await?;
        ensure!(greeting[0] == 5, "Invalid SOCKS greeting");
        let mut methods = vec![0u8; usize::from(greeting[1])];
        stream.read_exact(&mut methods).await?;
        ensure!(methods.contains(&2), "Authentication is required");
        stream.write_all(&[5, 2]).await?;
        ensure!(
            stream.read_u8().await? == 1,
            "Invalid authentication version"
        );
        let size = stream.read_u8().await?;
        let mut user = vec![0u8; usize::from(size)];
        stream.read_exact(&mut user).await?;
        let size = stream.read_u8().await?;
        let mut password = vec![0u8; usize::from(size)];
        stream.read_exact(&mut password).await?;
        ensure!(
            user == b"test-user" && password == b"test-pass",
            "Invalid proxy credentials"
        );
        stream.write_all(&[1, 0]).await?;
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        ensure!(header[..3] == [5, 1, 0], "Invalid SOCKS request");
        let host = match header[3] {
            1 => {
                let mut bytes = [0u8; 4];
                stream.read_exact(&mut bytes).await?;
                IpAddr::from(bytes)
            }
            4 => {
                let mut bytes = [0u8; 16];
                stream.read_exact(&mut bytes).await?;
                IpAddr::from(bytes)
            }
            _ => bail!("Expected an IP destination"),
        };
        (host.to_string(), stream.read_u16().await?)
    } else {
        let header = proxy::read_until(&mut stream, b"\r\n\r\n", 16384).await?;
        let text = std::str::from_utf8(&header)?;
        let parts: Vec<_> = text
            .lines()
            .next()
            .context("Missing CONNECT line")?
            .split_whitespace()
            .collect();
        ensure!(
            parts.len() == 3 && parts[0] == "CONNECT",
            "Expected CONNECT"
        );
        ensure!(
            text.contains("Proxy-Authorization: Basic dGVzdC11c2VyOnRlc3QtcGFzcw=="),
            "Invalid proxy credentials"
        );
        let (host, port) = parts[1].rsplit_once(':').context("Missing CONNECT port")?;
        (host.trim_matches(['[', ']']).to_owned(), port.parse()?)
    };
    let mut remote = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let record = json!({"source":stream.peer_addr()?.ip().to_string(),"host":host,"port":port,"protocol":if socks{"socks5"}else{"http"}});
    let mut output = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log.as_ref())?;
    writeln!(output, "{record}")?;
    stream
        .write_all(if socks {
            b"\x05\x00\x00\x01\0\0\0\0\0\0"
        } else {
            b"HTTP/1.1 200 Established\r\n\r\n"
        })
        .await?;
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}
async fn proxy_accept(listener: TcpListener, socks: bool, log: Arc<PathBuf>) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let log = log.clone();
        tokio::spawn(async move {
            let _ = proxy_connection(stream, socks, log).await;
        });
    }
}
async fn proxy_server(log: PathBuf) -> Result<()> {
    let http = TcpListener::bind("10.203.0.1:18801").await?;
    let socks = TcpListener::bind("10.203.0.1:18802").await?;
    println!("READY");
    std::io::stdout().flush()?;
    let log = Arc::new(log);
    tokio::try_join!(
        proxy_accept(http, false, log.clone()),
        proxy_accept(socks, true, log)
    )?;
    Ok(())
}
fn probe_command(
    host: &str,
    transport: &str,
    output: &Path,
    descendant: bool,
) -> Result<Vec<String>> {
    let mut args = vec![std::env::current_exe()?.to_string_lossy().into_owned()];
    if descendant {
        args.push("--descendant".into());
    }
    args.extend([
        "--connect".into(),
        host.into(),
        transport.into(),
        output.to_string_lossy().into_owned(),
    ]);
    Ok(args)
}
fn await_result(output: &Path) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(bytes) = fs::read(output)
            && let Ok(value) = serde_json::from_slice(&bytes)
        {
            return Ok(value);
        }
        ensure!(Instant::now() < deadline, "Probe output timed out");
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn check(actual: &Value, uid: u32, expected: Option<&str>) -> Result<()> {
    ensure!(
        actual["uid"] == uid && actual["euid"] == uid,
        "App did not drop credentials: {actual}"
    );
    match expected {
        Some(source) => ensure!(actual["source"] == source, "Unexpected source: {actual}"),
        None => ensure!(
            actual["source"].is_null(),
            "Traffic escaped controls: {actual}"
        ),
    };
    Ok(())
}
fn kernel_probe(
    uid: u32,
    group: &Path,
    public: &Path,
    host: &str,
    transport: &str,
    expected: Option<&str>,
    descendant: bool,
) -> Result<()> {
    let output = public.join(format!("{}.json", uuid::Uuid::new_v4()));
    let args = probe_command(host, transport, &output, descendant)?;
    let user = linux::user(uid)?;
    let environment = astroute_backend::daemon::launch_environment(uid, &json!({}), None)?;
    let (pid, mut gate) = linux::spawn_gated(&user, group, &args, &environment, &user.home)?;
    fs::write(group.join("cgroup.procs"), pid.to_string())?;
    gate.write_all(b"1")?;
    drop(gate);
    let result = await_result(&output).and_then(|value| check(&value, uid, expected));
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
        libc::waitpid(pid as i32, std::ptr::null_mut(), 0);
    }
    result
}
// Exercise the production client, peer-checked socket and shutdown path.
struct Session {
    helper: Background,
    uid: u32,
    config: PathBuf,
}
impl Session {
    fn client(&self, args: &[String], input: Option<&Value>) -> Result<Value> {
        let user = linux::user(self.uid)?;
        let mut child = Command::new(linux::helper_path()?)
            .arg("--client")
            .args(args)
            .uid(self.uid)
            .gid(user.gid)
            .env_clear()
            .env("XDG_CONFIG_HOME", &self.config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        if let Some(value) = input {
            serde_json::to_writer(child.stdin.take().unwrap(), value)?;
        } else {
            drop(child.stdin.take());
        }
        let output = child.wait_with_output()?;
        let response: Value = serde_json::from_slice(&output.stdout)?;
        ensure!(
            output.status.success() && response["ok"] == true,
            "Client failed: {response}"
        );
        Ok(response["data"].clone())
    }
    fn profile(&self, raw: Value) -> Result<Value> {
        self.client(&["save-proxy".into()], Some(&raw))
    }
    fn snapshot(&self) -> Result<Value> {
        self.client(&["snapshot".into()], None)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.helper.0.kill();
        let _ = self.helper.0.wait();
        let _ = astroute_backend::daemon::cleanup(self.uid);
        let _ = self.client(&["disable".into()], None);
    }
}
fn mount_tmpfs(path: &Path) -> Result<()> {
    ensure!(
        path.is_dir(),
        "Missing fixture mount point: {}",
        path.display()
    );
    linux::command(
        &[
            "/usr/bin/mount".into(),
            "-t".into(),
            "tmpfs".into(),
            "tmpfs".into(),
            path.to_string_lossy().into(),
        ],
        None,
        true,
    )?;
    Ok(())
}
fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(path.as_ptr(), uid, gid) } == 0,
        "Fixture ownership failed"
    );
    Ok(())
}
fn app_probe(
    agent: &mut Session,
    uid: u32,
    public: &Path,
    mut policy: Value,
    host: &str,
    transport: &str,
    expected: Option<&str>,
) -> Result<()> {
    let output = public.join(format!("{}.json", uuid::Uuid::new_v4()));
    policy["app_id"] = json!("astroute-integration");
    agent.client(&["save".into(), policy.to_string()], None)?;
    agent.client(
        &[
            "launch".into(),
            "astroute-integration".into(),
            "--".into(),
            host.into(),
            transport.into(),
            output.to_string_lossy().into(),
        ],
        None,
    )?;
    check(&await_result(&output)?, uid, expected)
}
fn integration() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Run with sudo unshare --net"
    );
    ensure!(
        fs::read_link("/proc/self/ns/net")? != fs::read_link("/proc/1/ns/net")?,
        "Refusing to change the host network namespace"
    );
    let uid: u32 = std::env::var("SUDO_UID")
        .context("SUDO_UID is required")?
        .parse()?;
    ensure!(uid > 0, "A non-root desktop user is required");
    ensure!(
        fs::read_link("/proc/self/ns/mnt")? != fs::read_link("/proc/1/ns/mnt")?,
        "Run inside an isolated mount namespace"
    );
    let native_root = PathBuf::from(format!("/sys/fs/cgroup/cosmic-netguard-{uid}"));
    ensure!(
        !native_root.exists(),
        "Disable existing controls before running this harness"
    );
    linux::command(
        &linux::args(&["/usr/bin/mount", "--make-rprivate", "/"]),
        None,
        true,
    )?;
    let user = linux::user(uid)?;
    mount_tmpfs(Path::new("/run"))?;
    mount_tmpfs(&user.home.join(".local/share/applications"))?;
    mount_tmpfs(&user.home.join(".local/state"))?;
    chown(&user.home.join(".local/share/applications"), uid, user.gid)?;
    chown(&user.home.join(".local/state"), uid, user.gid)?;
    let temporary = tempfile::tempdir()?;
    linux::mode(temporary.path(), 0o755)?;
    let public = temporary.path().join("output");
    fs::create_dir(&public)?;
    linux::mode(&public, 0o777)?;
    let executable = std::env::current_exe()?;
    let namespace = background(
        Command::new("/usr/bin/unshare")
            .args(["--net", "--"])
            .arg(&executable)
            .arg("--hold"),
    )?;
    let pid = namespace.0.id();
    ip(&["link", "set", "lo", "up"])?;
    peer(pid, &["link", "set", "lo", "up"])?;
    for (name, other, v4, v6) in [
        ("nga", "ngpa", "10.201.0", "2001:db8:1"),
        ("ngb", "ngpb", "10.202.0", "2001:db8:2"),
    ] {
        ip(&["link", "add", name, "type", "veth", "peer", "name", other])?;
        ip(&["link", "set", other, "netns", &pid.to_string()])?;
        ip(&["addr", "add", &format!("{v4}.1/24"), "dev", name])?;
        ip(&[
            "-6",
            "addr",
            "add",
            &format!("{v6}::1/64"),
            "dev",
            name,
            "nodad",
        ])?;
        ip(&["link", "set", name, "up"])?;
        peer(pid, &["addr", "add", &format!("{v4}.2/24"), "dev", other])?;
        peer(
            pid,
            &[
                "-6",
                "addr",
                "add",
                &format!("{v6}::2/64"),
                "dev",
                other,
                "nodad",
            ],
        )?;
        peer(pid, &["link", "set", other, "up"])?;
    }
    peer(pid, &["addr", "add", "10.203.0.1/32", "dev", "lo"])?;
    peer(
        pid,
        &["-6", "addr", "add", "2001:db8:3::1/128", "dev", "lo"],
    )?;
    for (family, a, b) in [
        ("-4", "10.201.0.2", "10.202.0.2"),
        ("-6", "2001:db8:1::2", "2001:db8:2::2"),
    ] {
        ip(&[family, "route", "add", "default", "via", a, "dev", "nga"])?;
        ip(&[
            family, "route", "add", "default", "via", b, "dev", "ngb", "table", "12345",
        ])?;
    }
    let _echo = background(
        Command::new("/usr/bin/nsenter")
            .args(["-t", &pid.to_string(), "-n", "--"])
            .arg(&executable)
            .arg("--server"),
    )?;
    let root = PathBuf::from(format!(
        "/sys/fs/cgroup/netguard-integration-{}",
        std::process::id()
    ));
    {
        let mut kernel =
            Kernel::with_paths(uid, root.clone(), temporary.path().join("routes.json"))?;
        let group = kernel.group("probe")?;
        let mut entry = Entry {
            policy: Policy {
                app_id: "probe".into(),
                mode: Mode::Allow,
                interface: None,
                proxy: None,
                proxy_fallback: Fallback::Block,
            },
            cgroup: group
                .strip_prefix("/sys/fs/cgroup")?
                .to_string_lossy()
                .into(),
            proxy_port: None,
            dns_port: None,
        };
        kernel.apply(&[entry.clone()])?;
        kernel_probe(
            uid,
            &group,
            &public,
            "10.203.0.1",
            "tcp",
            Some("10.201.0.1"),
            false,
        )?;
        kernel.bind(&group, Some("ngb"))?;
        entry.policy.interface = Some("ngb".into());
        kernel.apply(&[entry.clone()])?;
        for transport in ["tcp", "udp"] {
            for (host, source) in [
                ("10.203.0.1", "10.202.0.1"),
                ("2001:db8:3::1", "2001:db8:2::1"),
            ] {
                kernel_probe(uid, &group, &public, host, transport, Some(source), false)?;
            }
        }
        kernel_probe(
            uid,
            &group,
            &public,
            "10.203.0.1",
            "tcp",
            Some("10.202.0.1"),
            true,
        )?;
        entry.policy.mode = Mode::Block;
        kernel.apply(&[entry.clone()])?;
        for host in ["10.203.0.1", "2001:db8:3::1"] {
            for transport in ["tcp", "udp"] {
                kernel_probe(uid, &group, &public, host, transport, None, false)?;
            }
        }
        entry.policy.mode = Mode::Allow;
        kernel.apply(&[entry])?;
        ip(&["link", "set", "ngb", "down"])?;
        kernel.refresh_routes()?;
        for host in ["10.203.0.1", "2001:db8:3::1"] {
            kernel_probe(uid, &group, &public, host, "tcp", None, false)?;
        }
    }
    println!(
        "PASS selected interface, IPv4/IPv6 TCP/UDP, blocking, descendants, interface loss and cleanup"
    );
    ip(&["link", "set", "ngb", "up"])?;
    ip(&[
        "-6",
        "addr",
        "replace",
        "2001:db8:2::1/64",
        "dev",
        "ngb",
        "nodad",
    ])?;
    for (family, gateway) in [("-4", "10.202.0.2"), ("-6", "2001:db8:2::2")] {
        ip(&[
            family, "route", "replace", "default", "via", gateway, "dev", "ngb", "table", "12345",
        ])?;
    }
    let config = temporary.path().join("config");
    fs::create_dir(&config)?;
    chown(&config, uid, user.gid)?;
    let desktop = user
        .home
        .join(".local/share/applications/astroute-integration.desktop");
    fs::write(
        &desktop,
        format!(
            "[Desktop Entry]\nType=Application\nName=Astroute integration fixture\nExec={} --connect %F\n",
            desktop_quote(&executable.to_string_lossy())
        ),
    )?;
    let helper = Background(
        Command::new(linux::helper_path()?)
            .args(["--uid", &uid.to_string()])
            .spawn()?,
    );
    let mut agent = Session {
        helper,
        uid,
        config,
    };
    let socket = PathBuf::from(format!("/run/cosmic-netguard/{uid}/control.sock"));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        ensure!(
            Instant::now() < deadline && agent.helper.0.try_wait()?.is_none(),
            "Helper startup failed"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    for (mode, expected) in [("allow", Some("10.202.0.1")), ("block", None)] {
        app_probe(
            &mut agent,
            uid,
            &public,
            json!({"app_id":"test-command","mode":mode,"interface":"ngb"}),
            "10.203.0.1",
            "tcp",
            expected,
        )?;
    }
    app_probe(
        &mut agent,
        uid,
        &public,
        json!({"mode":"allow", "interface":"ng-missing"}),
        "10.203.0.1",
        "tcp",
        None,
    )?;
    ensure!(
        agent.snapshot()?["enabled"] == true,
        "Missing interface stopped the helper"
    );
    let proxy_log = temporary.path().join("connections.jsonl");
    let _proxies = background(
        Command::new("/usr/bin/nsenter")
            .args(["-t", &pid.to_string(), "-n", "--"])
            .arg(&executable)
            .arg("--proxy-server")
            .arg(&proxy_log),
    )?;
    let mut last = String::new();
    for (protocol, port) in [("http", 18801), ("socks5", 18802)] {
        let saved=agent.profile(json!({"name":protocol,"protocol":protocol,"host":"10.203.0.1","port":port,"username":"test-user","password":"test-pass"}))?;
        ensure!(
            saved["profile"].get("password").is_none(),
            "Credentials leaked in save response"
        );
        last = saved["profile"]["id"].as_str().unwrap().into();
        for host in ["10.203.0.1", "2001:db8:3::1"] {
            app_probe(
                &mut agent,
                uid,
                &public,
                json!({"app_id":"proxy-command","interface":"ngb","proxy":last}),
                host,
                "tcp",
                Some(host),
            )?;
        }
        app_probe(
            &mut agent,
            uid,
            &public,
            json!({"app_id":"proxy-command","interface":"ngb","proxy":last}),
            "10.203.0.1",
            "udp",
            None,
        )?;
        for line in fs::read_to_string(&proxy_log)?.lines() {
            let record: Value = serde_json::from_str(line)?;
            ensure!(
                record["source"] == "10.202.0.1",
                "Proxy used the wrong interface: {record}"
            );
        }
    }
    ip(&["-4", "route", "del", "default"])?;
    ip(&["-6", "route", "del", "default"])?;
    ip(&[
        "-4",
        "route",
        "add",
        "10.203.0.1/32",
        "via",
        "10.202.0.2",
        "dev",
        "ngb",
    ])?;
    for host in ["10.203.0.1", "2001:db8:3::1"] {
        app_probe(
            &mut agent,
            uid,
            &public,
            json!({"app_id":"proxy-command","interface":"ngb","proxy":last}),
            host,
            "tcp",
            Some(host),
        )?;
    }
    ensure!(
        !agent.snapshot()?.to_string().contains("test-pass"),
        "Credentials leaked in snapshot"
    );
    for process in inventory::processes(uid) {
        if process.argv.iter().any(|s| s == "--proxy-worker") {
            ensure!(
                fs::metadata(format!("/proc/{}", process.pid))?.uid() == uid,
                "Proxy worker still runs as root"
            );
        }
    }
    let offline = agent
        .profile(json!({"name":"Offline","protocol":"http","host":"10.203.0.1","port":18809}))?;
    let id = offline["profile"]["id"].clone();
    app_probe(
        &mut agent,
        uid,
        &public,
        json!({"app_id":"proxy-command","interface":"ngb","proxy":id}),
        "10.203.0.1",
        "tcp",
        None,
    )?;
    for (host, source) in [
        ("10.203.0.1", "10.202.0.1"),
        ("2001:db8:3::1", "2001:db8:2::1"),
    ] {
        app_probe(
            &mut agent,
            uid,
            &public,
            json!({"app_id":"proxy-command","interface":"ngb","proxy":id,"proxy_fallback":"direct"}),
            host,
            "tcp",
            Some(source),
        )?;
    }
    ip(&["link", "set", "ngb", "down"])?;
    app_probe(
        &mut agent,
        uid,
        &public,
        json!({"app_id":"proxy-command","interface":"ngb","proxy":id,"proxy_fallback":"direct"}),
        "10.203.0.1",
        "tcp",
        None,
    )?;
    ip(&["link", "set", "ngb", "up"])?;
    fs::write("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "1")?;
    let v4 = agent.profile(json!({"name":"IPv4 only", "protocol":"http", "host":"10.203.0.1", "port":18801, "username":"test-user", "password":"test-pass"}))?;
    app_probe(
        &mut agent,
        uid,
        &public,
        json!({"interface":"ngb", "proxy":v4["profile"]["id"]}),
        "10.203.0.1",
        "tcp",
        Some("10.203.0.1"),
    )?;
    agent.client(&["disable".into()], None)?;
    ensure!(
        !socket.exists() && !socket.with_file_name("active").exists(),
        "Shutdown completed before cleanup"
    );
    ensure!(
        !fs::read_to_string(&desktop)?.contains("X-Netguard-Managed"),
        "Launcher was not restored"
    );
    agent.helper.0.wait()?;
    // Simulate an ungraceful helper exit and use the real privileged recovery command.
    agent.helper = Background(
        Command::new(linux::helper_path()?)
            .args(["--uid", &uid.to_string()])
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        ensure!(Instant::now() < deadline, "Restart failed");
        std::thread::sleep(Duration::from_millis(50));
    }
    agent.client(&["apply".into()], None)?;
    agent.helper.0.kill()?;
    agent.helper.0.wait()?;
    ensure!(
        agent.snapshot().is_err(),
        "A dead helper was reported as safely inactive"
    );
    ensure!(
        agent
            .client(&["launch".into(), "astroute-integration".into()], None)
            .is_err(),
        "Stale controls allowed a direct launch"
    );
    ensure!(
        Command::new(linux::helper_path()?)
            .args(["--cleanup", "--uid", &uid.to_string()])
            .status()?
            .success(),
        "Privileged recovery failed"
    );
    agent.client(&["disable".into()], None)?;
    ensure!(
        !socket.exists() && !socket.with_file_name("active").exists(),
        "Recovery left stale state"
    );
    println!(
        "PASS real client IPC, launch gate, proxies, IPv4-only loopback, shutdown and crash recovery"
    );
    Ok(())
}
fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("--hold") => {
            println!("READY");
            std::io::stdout().flush()?;
            std::thread::sleep(Duration::from_secs(300));
            Ok(())
        }
        Some("--server") => echo_server(),
        Some("--proxy-server") => proxy::runtime()?.block_on(proxy_server(PathBuf::from(
            arguments.get(1).context("Missing log path")?,
        ))),
        Some("--connect") => {
            ensure!(arguments.len() == 4, "Expected host, transport and output");
            connect(&arguments[1], &arguments[2], Path::new(&arguments[3]))
        }
        Some("--descendant") => {
            let status = Command::new(std::env::current_exe()?)
                .args(&arguments[1..])
                .status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
        None => integration(),
        _ => bail!("Unknown harness command"),
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
