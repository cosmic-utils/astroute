use crate::{
    Result, inventory, linux,
    types::{Entry, Mode, valid_interface},
};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Path, PathBuf},
};

const LAN4: &str = "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4 }";
const LAN6: &str = "{ fc00::/7, fe80::/10, ff00::/8 }";
pub fn route_mark(uid: u32, interface: &str) -> u32 {
    let mut crc = u32::MAX;
    for byte in format!("{uid}:{interface}").bytes() {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    0x4e000000 | ((!crc) & 0x00ffffff)
}
pub fn group_key(id: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, id.as_bytes());
    format!(
        "app-{}",
        digest.as_ref()[..12]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}
fn matcher(entry: &Entry) -> Result<String> {
    let path = entry.cgroup.trim_matches('/');
    ensure!(
        !path.is_empty()
            && path
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_./:@+-\\".contains(&c)),
        "Unsupported cgroup path"
    );
    ensure!(
        entry
            .policy
            .interface
            .as_ref()
            .is_none_or(|s| valid_interface(s)),
        "Invalid network interface"
    );
    Ok(format!(
        "socket cgroupv2 level {} \"{}\"",
        path.split('/').count(),
        path.replace('\\', "\\\\")
    ))
}
pub fn render_rules(uid: u32, entries: &[Entry]) -> Result<String> {
    let matches: Vec<_> = entries.iter().map(matcher).collect::<Result<_>>()?;
    let mut lines = vec![
        format!("table inet netguard_{uid} {{"),
        format!("comment \"Netguard user {uid}\""),
        "chain output { type filter hook output priority 10; policy accept;".into(),
    ];
    for (e, m) in entries.iter().zip(&matches) {
        if e.policy.proxy.is_some() {
            for transport in ["udp", "tcp"] {
                lines.push(format!(
                    "{m} {transport} dport 53 counter reject with icmpx type admin-prohibited"
                ));
            }
            lines.extend([
                format!("{m} ip daddr 127.0.0.0/8 return"),
                format!("{m} ip6 daddr ::1 return"),
                format!("{m} counter reject with icmpx type admin-prohibited"),
            ]);
            continue;
        }
        lines.push(format!("{m} oifname \"lo\" return"));
        if e.policy.mode == Mode::Block {
            lines.push(format!(
                "{m} counter reject with icmpx type admin-prohibited"
            ));
            continue;
        }
        if let Some(interface) = &e.policy.interface {
            lines.push(format!(
                "{m} oifname != \"{interface}\" counter reject with icmpx type admin-prohibited"
            ));
        }
        if e.policy.mode == Mode::Local {
            lines.extend([
                format!("{m} ip daddr {LAN4} counter return"),
                format!("{m} ip6 daddr {LAN6} counter return"),
                format!("{m} counter reject with icmpx type admin-prohibited"),
            ]);
        } else {
            lines.push(format!("{m} counter return"));
        }
    }
    lines.extend([
        "}".into(),
        "chain input { type filter hook input priority 10; policy accept;".into(),
    ]);
    for (e, m) in entries.iter().zip(&matches) {
        lines.push(format!("{m} iifname \"lo\" return"));
        if e.policy.mode == Mode::Block || e.policy.proxy.is_some() {
            lines.push(format!("{m} counter drop"));
        } else if let Some(interface) = &e.policy.interface {
            lines.push(format!("{m} iifname != \"{interface}\" counter drop"));
        }
        if e.policy.mode == Mode::Local {
            lines.extend([
                format!("{m} ip saddr {LAN4} return"),
                format!("{m} ip6 saddr {LAN6} return"),
                format!("{m} counter drop"),
            ]);
        }
    }
    // Finalize destination NAT after conntrack, before TUN clients' redirects.
    lines.extend([
        "}".into(),
        "chain app_redirect { type nat hook output priority -160; policy accept;".into(),
    ]);
    for (e, m) in entries.iter().zip(&matches) {
        if e.policy.mode == Mode::Block {
            continue;
        }
        if e.policy.proxy.is_none() {
            if e.policy.interface.is_some() {
                for (family, protocol) in [("ip", "ipv4"), ("ip6", "ipv6")] {
                    for transport in ["udp", "tcp"] {
                        lines.push(format!("{m} meta nfproto {protocol} meta l4proto {transport} fib daddr type unicast counter dnat {family} to {family} daddr"));
                    }
                }
            }
            continue;
        }
        let Some(port) = e.proxy_port else {
            continue;
        };
        ensure!(port > 0, "Invalid relay port");
        if let Some(dns_port) = e.dns_port {
            ensure!(dns_port > 0, "Invalid DNS relay port");
            for transport in ["udp", "tcp"] {
                lines.push(format!(
                    "{m} {transport} dport 53 counter redirect to :{dns_port}"
                ));
            }
        }
        if e.policy.mode == Mode::Local {
            lines.extend([
                format!("{m} ip daddr {LAN4} meta l4proto tcp counter redirect to :{port}"),
                format!("{m} ip6 daddr {LAN6} meta l4proto tcp counter redirect to :{port}"),
            ]);
        } else {
            lines.extend([
                format!("{m} ip daddr != 127.0.0.0/8 meta l4proto tcp counter redirect to :{port}"),
                format!("{m} ip6 daddr != ::1 meta l4proto tcp counter redirect to :{port}"),
            ]);
        }
    }
    // Restore our socket mark after VPN clients replace packet marks.
    lines.extend([
        "}".into(),
        "chain interface_route { type route hook output priority -90; policy accept;".into(),
    ]);
    for (e, m) in entries.iter().zip(&matches) {
        if e.policy.mode != Mode::Block
            && (e.policy.interface.is_some() || e.policy.proxy.is_some())
        {
            lines.push(format!(
                "{m} socket mark & 0xff000000 == 0x4e000000 counter meta mark set socket mark"
            ));
        }
    }
    lines.extend(["}".into(), "}".into()]);
    Ok(format!("{}\n", lines.join("\n")))
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Instruction {
    pub code: u8,
    pub registers: u8,
    pub offset: i16,
    pub immediate: i32,
}
fn ins(code: u8, registers: u8, offset: i16, immediate: i32) -> Instruction {
    Instruction {
        code,
        registers,
        offset,
        immediate,
    }
}
pub fn interface_bind_instructions(interface: &str, ipv6: bool) -> Result<Vec<Instruction>> {
    ensure!(valid_interface(interface), "Invalid interface");
    let mut code = Vec::new();
    let mut labels = BTreeMap::new();
    let mut jumps = Vec::new();
    fn jump(
        code: &mut Vec<Instruction>,
        jumps: &mut Vec<(usize, &'static str)>,
        op: u8,
        reg: u8,
        imm: u32,
        label: &'static str,
    ) {
        jumps.push((code.len(), label));
        code.push(ins(op, reg, 0, imm as i32));
    }
    if ipv6 {
        for offset in [8, 12] {
            code.push(ins(0x61, 0x12, offset, 0));
            jump(&mut code, &mut jumps, 0x55, 2, 0, "bind");
        }
        code.push(ins(0x61, 0x12, 16, 0));
        jump(&mut code, &mut jumps, 0x16, 2, 0xffffu32.to_be(), "mapped");
        jump(&mut code, &mut jumps, 0x55, 2, 0, "bind");
        code.push(ins(0x61, 0x12, 20, 0));
        jump(&mut code, &mut jumps, 0x15, 2, 1u32.to_be(), "allow");
        jump(&mut code, &mut jumps, 0x05, 0, 0, "bind");
        labels.insert("mapped", code.len());
        code.push(ins(0x61, 0x12, 20, 0));
    } else {
        code.push(ins(0x61, 0x12, 4, 0));
    }
    code.push(ins(0x54, 2, 0, 0xff000000u32.to_be() as i32));
    jump(
        &mut code,
        &mut jumps,
        0x15,
        2,
        0x7f000000u32.to_be(),
        "allow",
    );
    labels.insert("bind", code.len());
    code.push(ins(0x79, 0x12, 64, 0));
    jump(&mut code, &mut jumps, 0x15, 2, 0, "deny");
    code.push(ins(0x61, 0x22, 0, 0));
    jump(&mut code, &mut jumps, 0x55, 2, 0, "allow");
    let mut name = [0u8; 16];
    name[..interface.len()].copy_from_slice(interface.as_bytes());
    for offset in (0..16).step_by(4) {
        code.push(ins(
            0x62,
            10,
            offset as i16 - 16,
            i32::from_ne_bytes(name[offset..offset + 4].try_into().unwrap()),
        ));
    }
    code.extend([
        ins(0xb7, 2, 0, libc::SOL_SOCKET),
        ins(0xb7, 3, 0, libc::SO_BINDTODEVICE),
        ins(0xbf, 0xa4, 0, 0),
        ins(0x07, 4, 0, -16),
        ins(0xb7, 5, 0, 16),
        ins(0x85, 0, 0, 49),
    ]);
    jump(&mut code, &mut jumps, 0x55, 0, 0, "deny");
    labels.insert("allow", code.len());
    code.extend([ins(0xb7, 0, 0, 1), ins(0x95, 0, 0, 0)]);
    labels.insert("deny", code.len());
    code.extend([ins(0xb7, 0, 0, 0), ins(0x95, 0, 0, 0)]);
    for (index, label) in jumps {
        code[index].offset = (labels[label] as isize - index as isize - 1) as i16;
    }
    Ok(code)
}
struct BpfSocketMark {
    cgroup: fs::File,
    links: Vec<OwnedFd>,
}
fn bpf(command: u32, attr: &mut [u8]) -> Result<i32> {
    let result = unsafe { libc::syscall(libc::SYS_bpf, command, attr.as_mut_ptr(), attr.len()) };
    if result < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(result as i32)
    }
}
fn set32(attr: &mut [u8], offset: usize, value: u32) {
    attr[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}
fn set64(attr: &mut [u8], offset: usize, value: u64) {
    attr[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}
impl BpfSocketMark {
    fn new(cgroup: &Path, mark: u32, interface: &str) -> Result<Self> {
        let mut program = Self {
            cgroup: fs::File::open(cgroup)?,
            links: Vec::new(),
        };
        program.attach(
            &[
                ins(0xb4, 2, 0, mark as i32),
                ins(0x63, 0x21, 16, 0),
                ins(0xb7, 0, 0, 1),
                ins(0x95, 0, 0, 0),
            ],
            9,
            2,
        )?;
        for (hook, ipv6) in [(10, false), (11, true), (14, false), (15, true)] {
            if ipv6 && !linux::ipv6_supported()? {
                continue;
            }
            program.attach(&interface_bind_instructions(interface, ipv6)?, 18, hook)?;
        }
        Ok(program)
    }
    fn attach(&mut self, code: &[Instruction], kind: u32, hook: u32) -> Result<()> {
        let mut log = [0u8; 16384];
        let mut attr = [0u8; 144];
        let license = b"GPL\0";
        set32(&mut attr, 0, kind);
        set32(&mut attr, 4, code.len() as u32);
        set64(&mut attr, 8, code.as_ptr() as u64);
        set64(&mut attr, 16, license.as_ptr() as u64);
        set32(&mut attr, 24, 1);
        set32(&mut attr, 28, log.len() as u32);
        set64(&mut attr, 32, log.as_mut_ptr() as u64);
        set32(&mut attr, 68, hook);
        let descriptor = bpf(5, &mut attr).with_context(|| {
            format!(
                "Unable to load socket routing program (hook {hook}): {}",
                String::from_utf8_lossy(&log).trim_end_matches('\0')
            )
        })?;
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        // Unpinned BPF links detach when the helper's descriptors close, including SIGKILL.
        let mut attach = [0u8; 32];
        set32(&mut attach, 0, descriptor.as_raw_fd() as u32);
        set32(&mut attach, 4, self.cgroup.as_raw_fd() as u32);
        set32(&mut attach, 8, hook);
        let link = bpf(28, &mut attach).with_context(|| {
            format!(
                "Unable to attach socket routing link (hook {hook}); cgroup BPF links are required"
            )
        })?;
        self.links.push(unsafe { OwnedFd::from_raw_fd(link) });
        Ok(())
    }

    fn detach(&mut self) -> Result<()> {
        while let Some(fd) = self.links.last() {
            let mut attr = [0u8; 4];
            set32(&mut attr, 0, fd.as_raw_fd() as u32);
            bpf(34, &mut attr).context("Unable to detach application routing link")?;
            self.links.pop();
        }
        Ok(())
    }
}
pub struct Kernel {
    pub root: PathBuf,
    uid: u32,
    table: String,
    has_table: bool,
    pub routes: BTreeMap<u32, String>,
    fingerprints: BTreeMap<(u32, String), String>,
    programs: BTreeMap<PathBuf, BpfSocketMark>,
    ownership: PathBuf,
}
impl Kernel {
    pub fn new(uid: u32) -> Result<Self> {
        let root = PathBuf::from(format!("/sys/fs/cgroup/cosmic-netguard-{uid}"));
        Self::with_paths(
            uid,
            root,
            PathBuf::from(format!("/run/cosmic-netguard/{uid}/routes.json")),
        )
    }
    pub fn with_paths(uid: u32, root: PathBuf, ownership: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)?;
        let table = format!("netguard_{uid}");
        let has_table = linux::command(
            &linux::args(&["/usr/bin/nft", "list", "table", "inet", &table]),
            None,
            false,
        )?
        .success;
        if has_table {
            let raw: Value = serde_json::from_str(
                &linux::command(
                    &linux::args(&["/usr/bin/nft", "-j", "list", "table", "inet", &table]),
                    None,
                    true,
                )?
                .stdout,
            )?;
            ensure!(
                raw["nftables"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.get("table"))
                    .next()
                    .is_some_and(|t| t["comment"] == format!("Netguard user {uid}")),
                "Firewall table {table} is already owned by another configuration"
            );
        }
        let mut kernel = Self {
            root,
            uid,
            table,
            has_table,
            routes: BTreeMap::new(),
            fingerprints: BTreeMap::new(),
            programs: BTreeMap::new(),
            ownership,
        };
        if kernel.ownership.exists() {
            let entries: Vec<Value> =
                serde_json::from_str(&linux::read_limited(&kernel.ownership, 65536)?)?;
            for entry in entries {
                let interface = entry["interface"]
                    .as_str()
                    .context("Invalid saved routing ownership")?;
                let mark = entry["mark"]
                    .as_u64()
                    .context("Invalid saved routing mark")?;
                ensure!(
                    valid_interface(interface) && mark == u64::from(route_mark(uid, interface)),
                    "Invalid saved routing ownership"
                );
                let mark = mark as u32;
                for &family in linux::ip_families()? {
                    let routes = table_routes(family, mark)?;
                    ensure!(
                        routes.iter().all(protocol_owned),
                        "Foreign routes were added to table {mark}"
                    );
                    let rules = inventory::ip_json(&[family, "rule", "show"])?;
                    let matching: Vec<_> = rules.iter().filter(|r| r["table"] == mark).collect();
                    ensure!(
                        matching.iter().all(|r| protocol_owned(r)),
                        "Foreign rules reference table {mark}"
                    );
                }
                kernel.routes.insert(mark, interface.into());
            }
        }
        Ok(kernel)
    }
    fn persist_routes(&self) -> Result<()> {
        let values: Vec<_> = self
            .routes
            .iter()
            .map(|(mark, interface)| json!({"mark":mark,"interface":interface}))
            .collect();
        linux::atomic_write(&self.ownership, &serde_json::to_vec(&values)?, 0o600)
    }
    pub fn apply(&mut self, entries: &[Entry]) -> Result<()> {
        let rules = render_rules(self.uid, entries)?;
        let rules = if self.has_table {
            format!("delete table inet {}\n{rules}", self.table)
        } else {
            rules
        };
        linux::command(
            &linux::args(&["/usr/bin/nft", "-f", "-"]),
            Some(&rules),
            true,
        )?;
        self.has_table = true;
        Ok(())
    }
    pub fn group(&self, key: &str) -> Result<PathBuf> {
        ensure!(
            !key.contains('/') && crate::types::valid_id(key, 128),
            "Invalid cgroup key"
        );
        let path = self.root.join(key);
        fs::create_dir_all(&path)?;
        Ok(path)
    }
    fn configure_route(&mut self, interface: &str) -> Result<u32> {
        ensure!(valid_interface(interface), "Invalid interface");
        linux::ifindex(interface)?;
        let mark = route_mark(self.uid, interface);
        if let Some(existing) = self.routes.get(&mark) {
            ensure!(
                existing == interface,
                "Network interface routing mark collision"
            );
            self.refresh_route(mark, interface)?;
            return Ok(mark);
        }
        for &family in linux::ip_families()? {
            ensure!(
                table_routes(family, mark)?.is_empty(),
                "Routing table {mark} is already in use"
            );
            for rule in inventory::ip_json(&[family, "rule", "show"])? {
                ensure!(
                    rule["table"] != mark
                        && rule["fwmark"] != format!("{mark:#x}")
                        && rule["fwmark"] != mark,
                    "Routing mark {mark:#x} is already in use"
                );
            }
        }
        self.routes.insert(mark, interface.into());
        self.persist_routes()?;
        let result = (|| -> Result<()> {
            self.refresh_route(mark, interface)?;
            for &family in linux::ip_families()? {
                route_rule(family, "add", mark)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.remove_route(mark);
            return Err(error);
        }
        Ok(mark)
    }
    pub fn invalidate_routes(&mut self) {
        self.fingerprints.clear();
    }
    pub fn refresh_routes(&mut self) -> Result<()> {
        for (mark, interface) in self.routes.clone() {
            self.refresh_route(mark, &interface)?;
        }
        Ok(())
    }
    fn refresh_route(&mut self, mark: u32, interface: &str) -> Result<()> {
        let table = mark.to_string();
        for &family in linux::ip_families()? {
            linux::command(
                &linux::args(&[
                    "/usr/bin/ip",
                    family,
                    "route",
                    "replace",
                    "unreachable",
                    "default",
                    "table",
                    &table,
                    "metric",
                    "42760",
                    "protocol",
                    "242",
                ]),
                None,
                true,
            )?;
            if interface == "lo" {
                if family == "-6" && !linux::ipv6_loopback()? {
                    continue;
                }
                linux::command(
                    &linux::args(&[
                        "/usr/bin/ip",
                        family,
                        "route",
                        "replace",
                        "default",
                        "dev",
                        "lo",
                        "src",
                        if family == "-4" { "127.0.0.1" } else { "::1" },
                        "table",
                        &table,
                        "metric",
                        "100",
                        "protocol",
                        "242",
                    ]),
                    None,
                    true,
                )?;
                continue;
            }
            let mut selected: Vec<_> =
                inventory::ip_json(&[family, "route", "show", "table", "all"])?
                    .into_iter()
                    .filter(|r| {
                        r["dev"] == interface
                            && r["table"] != mark
                            && !crate::system_route::owned_route(r)
                            && r["table"] != "local"
                            && r["table"] != 255
                            && r.get("type").is_none_or(|v| v == "unicast")
                            && !r["flags"]
                                .as_array()
                                .is_some_and(|flags| flags.iter().any(|f| f == "linkdown"))
                    })
                    .collect();
            let fingerprint = serde_json::to_string(&selected)?;
            let key = (mark, family.to_owned());
            if self.fingerprints.get(&key) == Some(&fingerprint) {
                continue;
            }
            linux::command(
                &linux::args(&[
                    "/usr/bin/ip",
                    family,
                    "route",
                    "flush",
                    "table",
                    &table,
                    "type",
                    "unicast",
                ]),
                None,
                false,
            )?;
            selected.sort_by_key(|r| r["dst"] == "default");
            for route in selected {
                let dst = route["dst"].as_str().unwrap_or("default");
                if dst != "default" {
                    let _: ipnet::IpNet = dst.parse()?;
                }
                let mut argv = linux::args(&[
                    "/usr/bin/ip",
                    family,
                    "route",
                    "replace",
                    dst,
                    "table",
                    &table,
                ]);
                if let Some(gateway) = route["gateway"].as_str() {
                    let _: IpAddr = gateway.parse()?;
                    argv.extend(linux::args(&["via", gateway]));
                }
                argv.extend(linux::args(&["dev", interface]));
                if let Some(source) = route["prefsrc"].as_str() {
                    let _: IpAddr = source.parse()?;
                    argv.extend(linux::args(&["src", source]));
                }
                argv.extend(linux::args(&[
                    "metric",
                    &route["metric"]
                        .as_u64()
                        .unwrap_or(100)
                        .min(42000)
                        .to_string(),
                    "protocol",
                    "242",
                ]));
                if route["gateway"].is_string() {
                    argv.push("onlink".into());
                }
                linux::command(&argv, None, true)?;
            }
            self.fingerprints.insert(key, fingerprint);
        }
        Ok(())
    }
    pub fn bind(&mut self, cgroup: &Path, interface: Option<&str>) -> Result<()> {
        self.programs.remove(cgroup);
        if let Some(interface) = interface {
            let mark = self.configure_route(interface)?;
            self.programs.insert(
                cgroup.to_owned(),
                BpfSocketMark::new(cgroup, mark, interface)?,
            );
        }
        Ok(())
    }
    pub fn unbind(&mut self, cgroup: &Path) {
        self.programs.remove(cgroup);
    }

    pub fn shutdown(&mut self) -> Result<()> {
        for program in self.programs.values_mut() {
            program.detach()?;
        }
        self.programs.clear();
        if self.firewall_exists()? {
            linux::command(
                &linux::args(&["/usr/bin/nft", "delete", "table", "inet", &self.table]),
                None,
                true,
            )
            .context("Unable to remove application firewall rules")?;
            ensure!(
                !self.firewall_exists()?,
                "Application firewall rules are still active"
            );
        }
        self.has_table = false;
        for mark in self.routes.keys().copied().collect::<Vec<_>>() {
            for &family in linux::ip_families()? {
                let rules: Vec<_> = inventory::ip_json(&[family, "rule", "show"])?
                    .into_iter()
                    .filter(|rule| rule["table"] == mark)
                    .collect();
                ensure!(
                    rules.iter().all(protocol_owned),
                    "Foreign rules reference table {mark}"
                );
                for _ in rules {
                    route_rule(family, "del", mark)?;
                }
                let routes = table_routes(family, mark)?;
                ensure!(
                    routes.iter().all(protocol_owned),
                    "Foreign routes were added to table {mark}"
                );
                if !routes.is_empty() {
                    linux::command(
                        &linux::args(&[
                            "/usr/bin/ip",
                            family,
                            "route",
                            "flush",
                            "table",
                            &mark.to_string(),
                        ]),
                        None,
                        true,
                    )
                    .context("Unable to remove application routes")?;
                }
                ensure!(
                    table_routes(family, mark)?.is_empty()
                        && !inventory::ip_json(&[family, "rule", "show"])?
                            .iter()
                            .any(|rule| rule["table"] == mark),
                    "Application routes are still active"
                );
            }
            self.routes.remove(&mark);
            self.persist_routes()?;
        }
        self.fingerprints.clear();
        Ok(())
    }

    fn firewall_exists(&self) -> Result<bool> {
        let output = linux::command(
            &linux::args(&["/usr/bin/nft", "-j", "list", "tables"]),
            None,
            true,
        )?;
        let tables: Value = serde_json::from_str(&output.stdout)?;
        Ok(tables["nftables"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|value| value.get("table"))
            .any(|table| table["family"] == "inet" && table["name"] == self.table))
    }
    fn remove_route(&mut self, mark: u32) {
        for &family in linux::ip_families().unwrap_or(&["-4", "-6"]) {
            let _ = route_rule(family, "del", mark);
            let _ = linux::command(
                &linux::args(&[
                    "/usr/bin/ip",
                    family,
                    "route",
                    "flush",
                    "table",
                    &mark.to_string(),
                ]),
                None,
                false,
            );
        }
        self.routes.remove(&mark);
        let _ = self.persist_routes();
    }
}
fn protocol_owned(value: &Value) -> bool {
    value["protocol"] == 242 || value["protocol"] == "242"
}
fn table_routes(family: &str, mark: u32) -> Result<Vec<Value>> {
    let out = linux::command(
        &linux::args(&[
            "/usr/bin/ip",
            "-j",
            family,
            "route",
            "show",
            "table",
            &mark.to_string(),
        ]),
        None,
        false,
    )?;
    if out.success {
        Ok(serde_json::from_str(&out.stdout)?)
    } else {
        ensure!(
            out.stderr.contains("FIB table does not exist"),
            "Cannot inspect application routes: {}",
            out.stderr.trim()
        );
        Ok(Vec::new())
    }
}
fn route_rule(family: &str, verb: &str, mark: u32) -> Result<()> {
    linux::command(
        &linux::args(&[
            "/usr/bin/ip",
            family,
            "rule",
            verb,
            "priority",
            "100",
            "fwmark",
            &format!("{mark:#x}"),
            "lookup",
            &mark.to_string(),
            "protocol",
            "242",
        ]),
        None,
        true,
    )?;
    Ok(())
}
impl Drop for Kernel {
    fn drop(&mut self) {
        self.programs.clear();
        if self.has_table {
            let _ = linux::command(
                &linux::args(&["/usr/bin/nft", "delete", "table", "inet", &self.table]),
                None,
                false,
            );
            self.has_table = false;
        }
        for mark in self.routes.keys().copied().collect::<Vec<_>>() {
            self.remove_route(mark);
        }
        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let _ = fs::remove_dir(entry.path());
            }
        }
        let _ = fs::remove_dir(&self.root);
    }
}
