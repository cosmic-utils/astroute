use crate::{
    linux,
    types::{Application, Process},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::LazyLock,
};

static RUNTIME: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^(?:python|pypy|perl|ruby|electron)[0-9]+(?:\.[0-9]+)*$").unwrap()
});
static ESCAPES: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\\x([0-9a-fA-F]{2})").unwrap());
static SCOPE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^app-(?:(?:cosmic|gnome)-)?(.+)-([0-9]+)\.scope$").unwrap()
});
static SERVICE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^app-(.+)@[^/]+\.service$").unwrap());
static UNIT: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^app-.+\.(?:scope|service)$").unwrap());

pub fn shared_runtime(path: &str) -> bool {
    let name = Path::new(path)
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("");
    [
        "env", "sh", "bash", "dash", "zsh", "fish", "busybox", "python", "python2", "python3",
        "pypy", "pypy3", "perl", "ruby", "node", "nodejs", "java", "mono", "dotnet", "electron",
    ]
    .contains(&name)
        || RUNTIME.is_match(name)
}
pub fn command_key(app: &Application) -> Vec<String> {
    let mut key = app.argv.clone();
    if let Some(first) = key.first_mut() {
        *first = linux::realpath(&linux::which(first, None))
            .to_string_lossy()
            .into();
    }
    key
}
pub fn scope_identity(unit: &str) -> (Option<String>, Option<u32>) {
    let unit = ESCAPES.replace_all(unit, |c: &regex::Captures<'_>| {
        (u8::from_str_radix(&c[1], 16).unwrap() as char).to_string()
    });
    if let Some(c) = SCOPE.captures(&unit) {
        return (Some(c[1].into()), c[2].parse().ok());
    }
    (SERVICE.captures(&unit).map(|c| c[1].into()), None)
}
pub fn discover(
    uid: u32,
    catalog: &[Application],
    saved: &BTreeSet<String>,
    processes: &[Process],
) -> BTreeMap<String, String> {
    let apps: BTreeMap<_, _> = catalog
        .iter()
        .filter(|a| a.controllable && !a.argv.is_empty())
        .map(|a| (a.id.clone(), a))
        .collect();
    let keys: BTreeMap<_, _> = apps
        .iter()
        .map(|(id, a)| (id.clone(), command_key(a)))
        .collect();
    let mut aliases: BTreeMap<Vec<String>, BTreeSet<String>> = BTreeMap::new();
    let mut executables: BTreeMap<String, BTreeSet<Vec<String>>> = BTreeMap::new();
    for (id, key) in &keys {
        aliases.entry(key.clone()).or_default().insert(id.clone());
        if !shared_runtime(&apps[id].argv[0]) && !shared_runtime(&key[0]) {
            executables
                .entry(key[0].clone())
                .or_default()
                .insert(key.clone());
        }
    }
    let prefix = format!("/user.slice/user-{uid}.slice/");
    let mut groups: BTreeMap<String, Vec<&Process>> = BTreeMap::new();
    for p in processes {
        if p.uid == uid
            && p.cgroup.starts_with(&prefix)
            && Path::new(&p.cgroup)
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|s| UNIT.is_match(s))
        {
            groups.entry(p.cgroup.clone()).or_default().push(p);
        }
    }
    let mut found = BTreeMap::new();
    for (path, members) in &groups {
        let (owner, _) =
            scope_identity(Path::new(path).file_name().unwrap().to_str().unwrap_or(""));
        let candidates = if let Some(mut owner) = owner {
            if !apps.contains_key(&owner)
                && let Some(base) = owner.strip_suffix(".desktop")
            {
                owner = base.into();
            }
            if saved.contains(&owner) && apps.contains_key(&owner) {
                found.insert(path.clone(), owner);
                continue;
            }
            keys.get(&owner)
                .and_then(|key| aliases.get(key))
                .cloned()
                .unwrap_or_default()
        } else {
            let identities: BTreeSet<_> = members
                .iter()
                .flat_map(|p| {
                    executables
                        .get(
                            &linux::realpath(Path::new(&p.exe))
                                .to_string_lossy()
                                .into_owned(),
                        )
                        .into_iter()
                        .flatten()
                        .cloned()
                })
                .collect();
            if identities.len() != 1 {
                continue;
            }
            aliases
                .get(identities.first().unwrap())
                .cloned()
                .unwrap_or_default()
        };
        let candidates: Vec<_> = candidates.intersection(saved).collect();
        if candidates.len() == 1 {
            found.insert(path.clone(), candidates[0].clone());
        }
    }
    let mut leaders = BTreeMap::new();
    let pipe_helper = linux::realpath(&linux::which("cat", None));
    for (path, id) in &found {
        let (_, leader) =
            scope_identity(Path::new(path).file_name().unwrap().to_str().unwrap_or(""));
        for p in &groups[path] {
            if Some(p.pid) == leader && !shared_runtime(&p.exe) {
                leaders.insert(p.pid, (id.clone(), linux::realpath(Path::new(&p.exe))));
            }
        }
    }
    for (path, members) in &groups {
        if found.contains_key(path) {
            continue;
        }
        let (_, leader) =
            scope_identity(Path::new(path).file_name().unwrap().to_str().unwrap_or(""));
        let Some((id, exe)) = leader.and_then(|pid| leaders.get(&pid)) else {
            continue;
        };
        if members.iter().all(|p| {
            let p = linux::realpath(Path::new(&p.exe));
            p == *exe
                || p == pipe_helper
                || (p.parent() == exe.parent()
                    && p.file_name()
                        .is_some_and(|n| n == "chrome_crashpad_handler" || n == "crashpad_handler"))
        }) {
            found.insert(path.clone(), id.clone());
        }
    }
    found
}
