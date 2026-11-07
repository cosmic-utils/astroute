use crate::{Result, inventory, linux, types::valid_id};
use anyhow::{Context, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path};

pub fn desktop_quote(arg: &str) -> String {
    format!(
        "\"{}\"",
        arg.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('`', "\\`")
            .replace('$', "\\$")
            .replace('%', "%%")
    )
}
pub fn set(app_id: &str, enabled: bool) -> Result<Value> {
    ensure!(valid_id(app_id, 241), "Invalid application ID");
    let (home, state) = inventory::user_paths(linux::uid())?;
    linux::private_dir(&state)?;
    let _lock = linux::lock(&state.join("launchers.lock"), false)?;
    let backup = state.join("originals").join(format!("{app_id}.desktop"));
    let origin = backup.with_extension("origin");
    let target = home
        .join(".local/share/applications")
        .join(format!("{app_id}.desktop"));
    if enabled {
        let app = inventory::applications(linux::uid(), false)?
            .into_iter()
            .find(|a| a.id == app_id && a.controllable)
            .context("Application does not support controlled launching")?;
        fs::create_dir_all(backup.parent().unwrap())?;
        if !backup.exists() {
            linux::atomic_write(
                &backup,
                linux::read_limited(Path::new(&app.path), 1024 * 1024)?.as_bytes(),
                0o600,
            )?;
            linux::atomic_write(&origin, app.path.as_bytes(), 0o600)?;
        }
        let original = linux::read_limited(&backup, 1024 * 1024)?;
        let mut command = [
            linux::helper_path()?.to_string_lossy().into_owned(),
            "--client".into(),
            "launch".into(),
            app_id.into(),
        ]
        .iter()
        .map(|s| desktop_quote(s))
        .collect::<Vec<_>>()
        .join(" ");
        if let Some(code) = inventory::desktop_input_code(&inventory::desktop_section(&original))? {
            command.push_str(" -- ");
            command.push_str(&code);
        }
        let mut lines = Vec::new();
        let mut main = false;
        let mut action = false;
        let mut inserted = false;
        for line in original.lines() {
            if line.trim().starts_with('[') {
                if main && !inserted {
                    append(&mut lines, &command);
                    inserted = true;
                }
                main = line.trim() == "[Desktop Entry]";
                action = line.trim().starts_with("[Desktop Action ");
            }
            if action {
                continue;
            }
            if main
                && let Some((key, _)) = line.split_once('=')
                && ["Exec", "DBusActivatable", "X-Netguard-Managed", "Actions"]
                    .contains(&key.trim())
            {
                continue;
            }
            lines.push(line.to_owned());
        }
        if main && !inserted {
            append(&mut lines, &command);
            inserted = true;
        }
        ensure!(inserted, "Invalid original desktop entry");
        fs::create_dir_all(target.parent().unwrap())?;
        linux::atomic_write(&target, format!("{}\n", lines.join("\n")).as_bytes(), 0o644)?;
    } else if backup.exists() {
        let text = linux::read_limited(&target, 1024 * 1024)?;
        ensure!(
            inventory::desktop_section(&text)
                .get("X-Netguard-Managed")
                .is_some_and(|s| s == "true"),
            "The desktop entry was changed outside Astroute; refusing to overwrite it"
        );
        let original_path = linux::read_limited(&origin, 4096)?;
        if Path::new(&original_path) == target {
            linux::atomic_write(
                &target,
                linux::read_limited(&backup, 1024 * 1024)?.as_bytes(),
                0o644,
            )?;
        } else {
            fs::remove_file(&target)?;
        }
        fs::remove_file(backup)?;
        let _ = fs::remove_file(origin);
    }
    Ok(
        json!({"message": if enabled {"Controlled launcher enabled"} else {"Original launcher restored"}}),
    )
}
fn append(lines: &mut Vec<String>, command: &str) {
    lines.extend([
        format!("Exec={command}"),
        "DBusActivatable=false".into(),
        "X-Netguard-Managed=true".into(),
    ]);
}

pub fn restore_all() -> Result<()> {
    let (home, state) = inventory::user_paths(linux::uid())?;
    let originals = match fs::read_dir(state.join("originals")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in originals {
        let path = entry?.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "desktop")
        {
            continue;
        }
        let Some(id) = path.file_stem().and_then(|id| id.to_str()) else {
            continue;
        };
        ensure!(valid_id(id, 241), "Invalid saved launcher ID");
        let target = home
            .join(".local/share/applications")
            .join(format!("{id}.desktop"));
        if !target.exists() {
            continue;
        }
        let section = inventory::desktop_section(&linux::read_limited(&target, 1024 * 1024)?);
        if section
            .get("X-Netguard-Managed")
            .is_some_and(|managed| managed == "true")
        {
            set(id, false).with_context(|| {
                format!("Controls are disabled, but the launcher for {id} could not be restored")
            })?;
        }
    }
    Ok(())
}
