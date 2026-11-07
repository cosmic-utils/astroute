use crate::{
    Result, linux,
    types::{Application, Process, valid_id, valid_interface},
};
use anyhow::{bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

pub fn ip_json(arguments: &[&str]) -> Result<Vec<Value>> {
    let mut argv = linux::args(&["/usr/bin/ip", "-j"]);
    argv.extend(linux::args(arguments));
    Ok(serde_json::from_str(
        &linux::command(&argv, None, true)?.stdout,
    )?)
}
pub fn interfaces() -> Result<Vec<Value>> {
    let mut defaults = BTreeSet::new();
    for &family in linux::ip_families()? {
        for route in ip_json(&[family, "route", "show", "table", "all"])? {
            if route["dst"] == "default"
                && let Some(name) = route["dev"].as_str()
            {
                defaults.insert(name.to_owned());
            }
        }
    }
    let mut found = Vec::new();
    for link in ip_json(&["address", "show"])? {
        let Some(name) = link["ifname"].as_str() else {
            continue;
        };
        if name == "lo" || !valid_interface(name) {
            continue;
        }
        let mut kind = if Path::new("/sys/class/net")
            .join(name)
            .join("wireless")
            .exists()
        {
            "Wi-Fi"
        } else {
            "Ethernet"
        };
        if link["link_type"] == "none"
            || ["tun", "tap", "wg", "sb-"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        {
            kind = "Tunnel / VPN";
        } else if ["veth", "br-", "docker", "virbr"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            kind = "Virtual";
        }
        let up = link["flags"]
            .as_array()
            .is_some_and(|flags| flags.iter().any(|v| v == "UP"))
            && link["operstate"] != "DOWN";
        let addresses: Vec<_> = link["addr_info"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|a| a["scope"] == "global")
            .filter_map(|a| a["local"].as_str())
            .collect();
        found.push(json!({"name":name,"index":link["ifindex"],"kind":kind,"up":up,"default":defaults.contains(name),"addresses":addresses}));
    }
    found.sort_by_key(|v| {
        (
            !v["default"].as_bool().unwrap_or(false),
            !v["up"].as_bool().unwrap_or(false),
            v["name"].as_str().unwrap_or("").to_owned(),
        )
    });
    Ok(found)
}
pub fn user_paths(uid: u32) -> Result<(PathBuf, PathBuf)> {
    let home = linux::user(uid)?.home;
    let state = home.join(".local/state/cosmic-netguard");
    Ok((home, state))
}
pub fn desktop_section(text: &str) -> BTreeMap<String, String> {
    let mut inside = false;
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == "[Desktop Entry]";
        } else if inside
            && !line.starts_with('#')
            && let Some((key, value)) = line.split_once('=')
        {
            result.insert(key.trim().into(), value.trim().into());
        }
    }
    result
}
pub fn desktop_argv(section: &BTreeMap<String, String>, path: &Path) -> Result<Vec<String>> {
    desktop_argv_with_inputs(section, path, &[])
}

pub fn desktop_input_code(section: &BTreeMap<String, String>) -> Result<Option<String>> {
    let words = shell_words::split(section.get("Exec").map(String::as_str).unwrap_or(""))?;
    let codes: Vec<_> = words
        .into_iter()
        .filter(|s| ["%f", "%F", "%u", "%U"].contains(&s.as_str()))
        .collect();
    ensure!(codes.len() <= 1, "Multiple desktop input field codes");
    Ok(codes.into_iter().next())
}

pub fn desktop_argv_with_inputs(
    section: &BTreeMap<String, String>,
    path: &Path,
    inputs: &[String],
) -> Result<Vec<String>> {
    ensure!(
        inputs.len() <= 256 && inputs.iter().all(|s| s.len() <= 16384 && !s.contains('\0')),
        "Invalid launch inputs"
    );
    desktop_input_code(section)?;
    let get = |key: &str| section.get(key).map(String::as_str).unwrap_or("");
    let mut result = Vec::new();
    for arg in shell_words::split(get("Exec"))? {
        if ["%f", "%u", "%F", "%U"].contains(&arg.as_str()) {
            result.extend(
                inputs
                    .iter()
                    .take(if arg == "%f" || arg == "%u" {
                        1
                    } else {
                        inputs.len()
                    })
                    .cloned(),
            );
            continue;
        }
        if ["%d", "%D", "%n", "%N", "%v", "%m"].contains(&arg.as_str()) {
            continue;
        }
        if arg == "%i" {
            if !get("Icon").is_empty() {
                result.extend(["--icon".into(), get("Icon").into()]);
            }
            continue;
        }
        let arg = arg
            .replace("%%", "\0")
            .replace(
                "%c",
                section
                    .get("Name")
                    .map(String::as_str)
                    .unwrap_or("Application"),
            )
            .replace("%k", &path.to_string_lossy());
        ensure!(
            !arg.as_bytes()
                .windows(2)
                .any(|w| w[0] == b'%' && w[1].is_ascii_alphabetic()),
            "Unsupported desktop entry field code"
        );
        result.push(arg.replace('\0', "%"));
    }
    ensure!(
        !result.is_empty() && !result[0].is_empty() && result.iter().all(|s| !s.contains('\0')),
        "No launch command"
    );
    Ok(result)
}
fn desktop_files(root: &Path, output: &mut Vec<PathBuf>, depth: usize) {
    if depth > 16 {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            desktop_files(&path, output, depth + 1);
        } else if path.extension().is_some_and(|s| s == "desktop") {
            output.push(path);
        }
    }
}
pub fn applications(uid: u32, include_nodisplay: bool) -> Result<Vec<Application>> {
    let (home, state) = user_paths(uid)?;
    let roots = [
        home.join(".local/share/applications"),
        PathBuf::from("/usr/local/share/applications"),
        PathBuf::from("/usr/share/applications"),
        home.join(".local/share/flatpak/exports/share/applications"),
        PathBuf::from("/var/lib/flatpak/exports/share/applications"),
    ];
    let mut found = BTreeMap::new();
    for root in roots {
        let mut paths = Vec::new();
        desktop_files(&root, &mut paths, 0);
        paths.sort();
        for path in paths {
            let Some(relative) = path.strip_prefix(&root).ok().and_then(Path::to_str) else {
                continue;
            };
            let id = relative.trim_end_matches(".desktop").replace('/', "-");
            if !valid_id(&id, 241) || found.contains_key(&id) {
                continue;
            }
            let parsed = (|| -> Result<Application> {
                let mut original = path.clone();
                let mut section = desktop_section(&linux::read_limited(&path, 1024 * 1024)?);
                let managed_launcher = section
                    .get("X-Netguard-Managed")
                    .is_some_and(|v| v == "true");
                if managed_launcher {
                    original = state.join("originals").join(format!("{id}.desktop"));
                    section = desktop_section(&linux::read_limited(&original, 1024 * 1024)?);
                }
                let get = |key: &str, default: &str| {
                    section.get(key).cloned().unwrap_or_else(|| default.into())
                };
                if get("Type", "Application") != "Application"
                    || get("Hidden", "") == "true"
                    || (!include_nodisplay && get("NoDisplay", "") == "true")
                {
                    bail!("Hidden desktop entry");
                }
                let argv = desktop_argv(&section, &original)?;
                let reason = if !get("X-Flatpak", "").is_empty()
                    || Path::new(&argv[0])
                        .file_name()
                        .is_some_and(|s| s.to_string_lossy().contains("flatpak"))
                {
                    "Flatpak creates its own scope; controlled launching is not supported yet."
                } else if get("Terminal", "") == "true" {
                    "Launch this terminal tool using the command-line client."
                } else {
                    ""
                };
                Ok(Application {
                    id: id.clone(),
                    name: get("Name", &id),
                    icon: get("Icon", "application-x-executable"),
                    argv,
                    path: original.to_string_lossy().into(),
                    working_dir: get("Path", &home.to_string_lossy()),
                    controllable: reason.is_empty(),
                    reason: reason.into(),
                    managed_launcher,
                })
            })();
            if let Ok(app) = parsed {
                found.insert(id, app);
            }
        }
    }
    let mut apps: Vec<_> = found.into_values().collect();
    apps.sort_by_key(|a| a.name.to_lowercase());
    Ok(apps)
}
pub fn process_info(pid: u32) -> Option<Process> {
    let path = PathBuf::from(format!("/proc/{pid}"));
    let status = fs::read_to_string(path.join("status")).ok()?;
    let uid = status
        .lines()
        .find(|l| l.starts_with("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let cgroup = fs::read_to_string(path.join("cgroup"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_owned)?;
    Some(Process {
        pid,
        uid,
        cgroup,
        name: fs::read_to_string(path.join("comm")).ok()?.trim().into(),
        exe: fs::read_link(path.join("exe"))
            .ok()?
            .to_string_lossy()
            .into(),
        argv: String::from_utf8_lossy(&fs::read(path.join("cmdline")).ok()?)
            .trim_matches('\0')
            .split('\0')
            .map(str::to_owned)
            .collect(),
    })
}
pub fn processes(uid: u32) -> Vec<Process> {
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .filter_map(process_info)
        .filter(|p| p.uid == uid)
        .collect()
}
pub fn connections(uid: u32) -> Vec<Value> {
    let by_pid: BTreeMap<_, _> = processes(uid).into_iter().map(|p| (p.pid, p)).collect();
    let Ok(output) = linux::command(
        &linux::args(&["/usr/bin/ss", "-H", "-t", "-u", "-n", "-p", "-O"]),
        None,
        true,
    ) else {
        return Vec::new();
    };
    let pattern = regex::Regex::new(r"pid=(\d+)").unwrap();
    let mut result = Vec::new();
    for line in output.stdout.lines() {
        let columns: Vec<_> = line.split_whitespace().collect();
        if columns.len() < 6 {
            continue;
        }
        let pids: BTreeSet<u32> = pattern
            .captures_iter(line)
            .filter_map(|c| c[1].parse().ok())
            .collect();
        for pid in pids {
            if let Some(p) = by_pid.get(&pid) {
                result.push(json!({"pid":p.pid,"name":p.name,"exe":p.exe,"cgroup":p.cgroup,"protocol":columns[0],"state":columns[1],"local":columns[4],"remote":columns[5]}));
                if result.len() == 500 {
                    return result;
                }
            }
        }
    }
    result
}
pub fn snapshot(uid: u32) -> Result<Value> {
    Ok(
        json!({"enabled":false,"apps":applications(uid,false)?,"interfaces":interfaces()?,"connections":connections(uid),"policies":[],"active":[],"events":[],"message":"Enable network controls to apply rules. Monitoring is available without authentication."}),
    )
}
