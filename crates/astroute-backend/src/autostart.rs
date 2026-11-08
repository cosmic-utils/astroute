use crate::{Result, inventory, launcher, linux};
use anyhow::{Context, ensure};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

const ENTRY: &str = "autostart/io.github.astroute.Astroute.desktop";

pub fn enabled() -> Result<bool> {
    let mut directories = vec![linux::config_home()?];
    directories.extend(
        std::env::split_paths(
            &std::env::var_os("XDG_CONFIG_DIRS").unwrap_or_else(|| "/etc/xdg".into()),
        )
        .filter(|path| path.is_absolute()),
    );
    for directory in directories {
        let text = match linux::read_limited(&directory.join(ENTRY), 64 * 1024) {
            Ok(text) => text,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error.context("Unable to read startup settings")),
        };
        let entry = inventory::desktop_section(&text);
        return Ok(entry
            .get("Type")
            .is_some_and(|value| value == "Application")
            && entry.get("Hidden").is_none_or(|value| value != "true")
            && entry
                .get("X-GNOME-Autostart-enabled")
                .is_none_or(|value| value != "false"));
    }
    Ok(false)
}

pub fn set(enabled: bool, executable: &Path) -> Result<()> {
    let executable_text = executable
        .to_str()
        .context("Invalid startup executable path")?;
    ensure!(
        executable.is_absolute() && !executable_text.chars().any(char::is_control),
        "Startup executable must be an absolute path without control characters"
    );
    let metadata = executable
        .metadata()
        .context("Startup executable is unavailable")?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "Startup executable is not an executable file"
    );
    let path = linux::config_home()?.join(ENTRY);
    fs::create_dir_all(path.parent().unwrap()).context("Unable to create startup directory")?;
    // Desktop entry string escaping is applied after quoting the Exec argument.
    let command = launcher::desktop_quote(executable_text).replace('\\', "\\\\");
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=Astroute\nExec={command}\nIcon=io.github.astroute.Astroute\nTerminal=false\nStartupNotify=false\nHidden={}\n",
        !enabled
    );
    // A hidden user entry also overrides any system-wide startup entry.
    linux::atomic_write(&path, entry.as_bytes(), 0o644).context("Unable to save startup settings")
}
