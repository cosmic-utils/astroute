use astroute_backend::{
    daemon, dns, inventory, kernel, linux, proxy, scopes,
    store::Store,
    types::{Application, Entry, Fallback, Mode, Policy, Process, Profile},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn profile(changes: Value) -> Profile {
    let mut raw =
        json!({"id":"office","name":"Office","protocol":"socks5","host":"127.0.0.1","port":1080});
    raw.as_object_mut()
        .unwrap()
        .extend(changes.as_object().unwrap().clone());
    Profile::parse(&raw, None).unwrap()
}
fn entry(policy: Value) -> Entry {
    Entry {
        policy: Policy::parse(&policy).unwrap(),
        cgroup: "netguard/app".into(),
        proxy_port: None,
        dns_port: None,
    }
}
fn app(id: &str, executable: &str) -> Application {
    Application {
        id: id.into(),
        name: id.into(),
        icon: "browser".into(),
        argv: vec![executable.into()],
        path: "/a.desktop".into(),
        working_dir: "/tmp".into(),
        controllable: true,
        reason: String::new(),
        managed_launcher: false,
    }
}
fn process(pid: u32, unit: &str, exe: &str) -> Process {
    Process {
        pid,
        uid: 1000,
        name: "browser".into(),
        exe: exe.into(),
        cgroup: format!("/user.slice/user-1000.slice/app.slice/{unit}"),
        argv: vec![exe.into()],
    }
}

#[test]
fn policy_rejects_injection_and_invalid_modes() {
    for raw in [
        json!({"app_id":"../root"}),
        json!({"app_id":"firefox","mode":"run-root"}),
        json!({"app_id":"firefox","interface":"eth0\"; drop;"}),
        json!({"app_id":"firefox","interface":"lo"}),
        json!({"app_id":"firefox","proxy_fallback":"random"}),
    ] {
        assert!(Policy::parse(&raw).is_err());
    }
    let policy = Policy::parse(&json!({"app_id":"firefox","interface":""})).unwrap();
    assert_eq!(policy.interface, None);
    assert_eq!(policy.proxy_fallback, Fallback::Block);
}
#[test]
fn launch_environment_does_not_inherit_privileged_settings() {
    let env=daemon::launch_environment(linux::uid(),&json!({"LD_PRELOAD":"/tmp/evil.so","PYTHONPATH":"/tmp","HOME":"/root","WAYLAND_DISPLAY":"wayland-1"}),None).unwrap();
    assert!(!env.contains_key("LD_PRELOAD"));
    assert!(!env.contains_key("PYTHONPATH"));
    assert_eq!(
        env["HOME"],
        linux::user(linux::uid()).unwrap().home.to_string_lossy()
    );
    assert_eq!(env["WAYLAND_DISPLAY"], "wayland-1");
}
#[test]
fn desktop_arguments_preserve_quotes_and_literal_substitution() {
    let section = inventory::desktop_section(
        "[Desktop Entry]\nName=My Browser\nIcon=browser\nExec=browser \"two words\" %U %% %i %c \"$(touch /tmp/nope)\"\n",
    );
    assert_eq!(
        inventory::desktop_argv(&section, Path::new("/a.desktop")).unwrap(),
        [
            "browser",
            "two words",
            "%",
            "--icon",
            "browser",
            "My Browser",
            "$(touch /tmp/nope)"
        ]
    );
}
#[test]
fn proxy_validation_preserves_credentials_and_public_redaction() {
    for host in [
        "https://proxy.example",
        "proxy.example/path",
        "x\r\nHost: evil",
        "proxy:80",
        " ",
    ] {
        assert!(Profile::parse(&json!({"name":"Test","host":host,"port":80}), None).is_err());
    }
    for port in [json!(0), json!(65536), json!(true), json!("8080")] {
        assert!(
            Profile::parse(&json!({"name":"Test","host":"localhost","port":port}), None).is_err()
        );
    }
    assert_eq!(profile(json!({"host":"[::1]"})).host, "::1");
    assert!(
        profile(json!({"host":"bücher.example"}))
            .host
            .starts_with("xn--")
    );
    let original = profile(json!({"username":"user","password":"secret"}));
    let mut raw = serde_json::to_value(&original).unwrap();
    raw["password"] = Value::Null;
    assert_eq!(
        Profile::parse(&raw, Some(&original)).unwrap().password,
        "secret"
    );
    raw["username"] = json!("other");
    assert!(Profile::parse(&raw, Some(&original)).is_err());
    raw["username"] = json!("");
    assert!(
        Profile::parse(&raw, Some(&original))
            .unwrap()
            .password
            .is_empty()
    );
    let public = original.public();
    assert_eq!(public["has_password"], true);
    assert!(public.get("password").is_none());
    assert!(!public.to_string().contains("secret"));
}
#[test]
fn stores_keep_private_edits_revisions_and_deletions() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store {
        directory: temporary.path().join("config"),
    };
    let original =
        serde_json::to_value(profile(json!({"username":"user","password":"secret"}))).unwrap();
    let first = store.save_profile(&original).unwrap();
    let mut edit = original.clone();
    edit["name"] = json!("Renamed");
    edit["password"] = Value::Null;
    let second = store.save_profile(&edit).unwrap();
    assert_ne!(first.revision, second.revision);
    assert_eq!(store.profile("office").unwrap().revision, second.revision);
    edit["password"] = json!("new-secret");
    let third = store.save_profile(&edit).unwrap();
    assert_ne!(second.revision, third.revision);
    assert!(!third.public().to_string().contains("new-secret"));
    assert_eq!(store.profile("office").unwrap().password, "new-secret");
    assert_eq!(store.profile("office").unwrap().name, "Renamed");
    assert_eq!(
        fs::metadata(&store.directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(store.directory.join("proxies.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    store.remove("proxies", "office").unwrap();
    assert!(store.profiles().unwrap().is_empty());
    store
        .save_rule(&json!({"app_id":"firefox","mode":"block"}))
        .unwrap();
    assert_eq!(store.rules().unwrap()["firefox"].policy.mode, Mode::Block);
    store.remove("rules", "firefox").unwrap();
    assert!(store.rules().unwrap().is_empty());
    fs::write(
        store.directory.join("rules.json"),
        r#"{"version":1,"rules":[{"app_id":"firefox","mode":"local"}]}"#,
    )
    .unwrap();
    assert_eq!(store.rules().unwrap()["firefox"].policy.mode, Mode::Local);
}
#[test]
fn native_client_saves_profiles_privately_without_authentication() {
    let temporary = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_astroute-helper"))
        .args(["--client", "save-proxy"])
        .env("XDG_CONFIG_HOME", temporary.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let raw=serde_json::to_vec(&json!({"id":"office","name":"Office","protocol":"http","host":"proxy.example","port":8080,"username":"user","password":"test-secret"})).unwrap();
    child.stdin.take().unwrap().write_all(&raw).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["data"]["profile"].get("password").is_none());
    let store = Store {
        directory: temporary.path().join("cosmic-netguard"),
    };
    assert_eq!(store.profile("office").unwrap().password, "test-secret");
}
#[test]
fn tun_bypass_preserves_both_transports_and_families() {
    let e = entry(json!({"app_id":"firefox","interface":"wlan0"}));
    let rules = kernel::render_rules(1000, &[e]).unwrap();
    assert!(rules.contains("hook output priority -160"));
    assert!(rules.contains("hook output priority -90"));
    assert!(rules.contains("meta mark set socket mark"));
    for (family, protocol) in [("ip", "ipv4"), ("ip6", "ipv6")] {
        for transport in ["tcp", "udp"] {
            assert!(rules.contains(&format!("meta nfproto {protocol} meta l4proto {transport} fib daddr type unicast counter dnat {family} to {family} daddr")));
        }
    }
    assert!(rules.contains("oifname != \"wlan0\""));
    assert!(rules.contains("iifname != \"wlan0\""));
    let automatic = kernel::render_rules(1000, &[entry(json!({"app_id":"firefox"}))]).unwrap();
    assert!(!automatic.contains("dnat"));
    let mut invalid = entry(json!({"app_id":"firefox"}));
    invalid.cgroup = "x\" drop".into();
    assert!(kernel::render_rules(1000, &[invalid]).is_err());
}
#[test]
fn proxied_dns_is_captured_before_tcp_and_uncaptured_dns_is_blocked() {
    let mut e = entry(json!({"app_id":"firefox","proxy":"office","interface":"wlan0"}));
    e.proxy_port = Some(18000);
    e.dns_port = Some(18001);
    let rules = kernel::render_rules(1000, &[e]).unwrap();
    for transport in ["udp", "tcp"] {
        assert!(rules.contains(&format!("{transport} dport 53 counter redirect to :18001")));
        assert!(rules.contains(&format!("{transport} dport 53 counter reject")));
    }
    assert!(
        rules.find("dport 53 counter redirect").unwrap()
            < rules.find("redirect to :18000").unwrap()
    );
    assert!(
        rules.find("dport 53 counter reject").unwrap()
            < rules.find("ip daddr 127.0.0.0/8 return").unwrap()
    );
}
#[test]
fn routing_ids_are_scoped_and_ipv6_binding_handles_mapped_addresses() {
    assert_eq!(kernel::group_key("firefox").len(), 28);
    assert_eq!(kernel::route_mark(1000, "eth0") & 0xff000000, 0x4e000000);
    assert_ne!(
        kernel::route_mark(1000, "eth0"),
        kernel::route_mark(1001, "eth0")
    );
    let code = kernel::interface_bind_instructions("wlan0", true).unwrap();
    assert!(
        code.iter()
            .any(|i| i.code == 0x16 && i.immediate == 0xffffu32.to_be() as i32)
    );
    assert!(code.iter().any(|i| i.code == 0x79 && i.offset == 64));
    assert!(code.iter().any(|i| i.code == 0x85 && i.immediate == 49));
}
#[test]
fn chrome_hidden_alias_and_original_wrapper_scope_match() {
    let catalog = vec![
        app("google-chrome", "/opt/google/chrome/google-chrome"),
        app("com.google.Chrome", "/opt/google/chrome/google-chrome"),
    ];
    let saved = BTreeSet::from(["google-chrome".into()]);
    let processes = vec![
        process(
            42,
            "app-cosmic-com.google.Chrome-42.scope",
            "/opt/google/chrome/chrome",
        ),
        process(
            43,
            "app-google-chrome-42.scope",
            "/opt/google/chrome/chrome",
        ),
        process(44, "app-google-chrome-42.scope", "/usr/bin/cat"),
    ];
    let found = scopes::discover(1000, &catalog, &saved, &processes);
    assert_eq!(found.len(), 2);
    assert!(found.values().all(|id| id == "google-chrome"));
    assert_eq!(
        scopes::scope_identity(r"app-cosmic-google\x2dchrome-42.scope"),
        (Some("google-chrome".into()), Some(42))
    );
}
#[test]
fn shared_terminals_and_conflicting_desktop_owners_are_not_adopted() {
    let catalog = vec![
        app("firefox", "/opt/firefox/firefox"),
        app("terminal", "/usr/bin/terminal"),
    ];
    let saved = BTreeSet::from(["firefox".into()]);
    let mut browser = process(42, "app-terminal-41.scope", "/opt/firefox/firefox");
    assert!(scopes::discover(1000, &catalog, &saved, std::slice::from_ref(&browser)).is_empty());
    browser.cgroup = "/user.slice/user-1000.slice/session-2.scope".into();
    assert!(scopes::discover(1000, &catalog, &saved, &[browser]).is_empty());
}
#[test]
fn dns_bounds_and_failure_frames_are_validated() {
    let query = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
    ];
    assert_eq!(dns::question(&query).unwrap(), &query[12..]);
    let reply = dns::short_reply(&query, 0x8182).unwrap();
    assert_eq!(&reply[..4], &[0x12, 0x34, 0x81, 0x82]);
    assert_eq!(&reply[12..], &query[12..]);
    for size in 0..query.len() {
        assert!(dns::question(&query[..size]).is_err());
    }
    let mut invalid = query;
    invalid[12] = 0xff;
    assert!(dns::question(&invalid).is_err());
}
#[tokio::test(flavor = "current_thread")]
async fn http_connect_preserves_tunnel_bytes_and_authenticates() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let header = proxy::read_until(&mut stream, b"\r\n\r\n", 16384)
            .await
            .unwrap();
        let text = String::from_utf8(header).unwrap();
        assert!(text.contains("CONNECT [2001:db8::1]:443 HTTP/1.1"));
        assert!(text.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
        stream
            .write_all(b"HTTP/1.1 200 Established\r\n\r\ntunnel data")
            .await
            .unwrap();
    });
    let p = profile(json!({"protocol":"http","port":port,"username":"user","password":"pass"}));
    let mut stream = proxy::open_tunnel(&p, "2001:db8::1", 443).await.unwrap();
    let mut data = String::new();
    stream.read_to_string(&mut data).await.unwrap();
    assert_eq!(data, "tunnel data");
    server.await.unwrap();
}
#[tokio::test(flavor = "current_thread")]
async fn socks5_rejects_authentication_downgrade() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        stream.write_all(&[5, 0]).await.unwrap();
    });
    let p = profile(json!({"port":port,"username":"user","password":"pass"}));
    assert!(proxy::open_tunnel(&p, "192.0.2.1", 443).await.is_err());
    server.await.unwrap();
}
#[tokio::test(flavor = "current_thread")]
async fn socks5_authentication_and_ipv6_destination() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        stream.write_all(&[5, 2]).await.unwrap();
        let mut auth = [0; 11];
        stream.read_exact(&mut auth).await.unwrap();
        assert_eq!(&auth, b"\x01\x04user\x04pass");
        stream.write_all(&[1, 0]).await.unwrap();
        let mut request = [0; 22];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..4], &[5, 1, 0, 4]);
        assert_eq!(
            &request[4..20],
            &"2001:db8::123"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(&request[20..], &8443u16.to_be_bytes());
        stream
            .write_all(b"\x05\x00\x00\x01\0\0\0\0\0\0socks data")
            .await
            .unwrap();
    });
    let p = profile(json!({"port":port,"username":"user","password":"pass"}));
    let mut stream = proxy::open_tunnel(&p, "2001:db8::123", 8443).await.unwrap();
    let mut data = String::new();
    stream.read_to_string(&mut data).await.unwrap();
    assert_eq!(data, "socks data");
    server.await.unwrap();
}

#[test]
fn desktop_inputs_keep_their_position_without_shell_evaluation() {
    let path = std::path::Path::new("/tmp/browser.desktop");
    let inputs = vec![
        "https://example.test/?q=$(id)".into(),
        "/tmp/a b.txt".into(),
    ];
    let section = inventory::desktop_section("[Desktop Entry]\nExec=browser --open %U --after\n");
    assert_eq!(
        inventory::desktop_input_code(&section).unwrap().as_deref(),
        Some("%U")
    );
    assert_eq!(
        inventory::desktop_argv_with_inputs(&section, path, &inputs).unwrap(),
        vec!["browser", "--open", &inputs[0], &inputs[1], "--after"]
    );
    let section = inventory::desktop_section("[Desktop Entry]\nExec=viewer %f\n");
    assert_eq!(
        inventory::desktop_argv_with_inputs(&section, path, &inputs).unwrap(),
        vec!["viewer", &inputs[0]]
    );
    assert!(
        inventory::desktop_argv_with_inputs(&section, path, &["bad\0argument".into()]).is_err()
    );
    let section = inventory::desktop_section("[Desktop Entry]\nExec=viewer %F %U\n");
    assert!(inventory::desktop_argv(&section, path).is_err());
}
#[test]
fn limited_reads_reject_fifos_and_accept_regular_symlink_targets() {
    let temporary = tempfile::tempdir().unwrap();
    let fifo = temporary.path().join("blocked.desktop");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(linux::read_limited(&fifo, 1024).is_err());
    let regular = temporary.path().join("regular.desktop");
    fs::write(&regular, "[Desktop Entry]").unwrap();
    let link = temporary.path().join("linked.desktop");
    std::os::unix::fs::symlink(&regular, &link).unwrap();
    assert_eq!(linux::read_limited(&link, 1024).unwrap(), "[Desktop Entry]");
    assert!(linux::read_limited(temporary.path(), 1024).is_err());
}
