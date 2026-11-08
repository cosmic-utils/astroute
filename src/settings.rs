use semver::Version;
use std::{io, process::Stdio, time::Duration};
use tokio::{process::Command, time::timeout};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const RELEASES: &str = "https://github.com/cosmic-utils/astroute/releases";
const LATEST_RELEASE: &str = "https://github.com/cosmic-utils/astroute/releases/latest";
const RELEASE_BASE: &str = "https://github.com/cosmic-utils/astroute/releases/tag/";

#[derive(Default)]
pub struct State {
    pub autostart: Option<bool>,
    pub loading_autostart: bool,
    pub saving_autostart: bool,
    pub autostart_error: Option<String>,
    pub update: Update,
    pub opening_release: bool,
    pub release_error: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub enum Update {
    #[default]
    Idle,
    Checking,
    Current,
    Available(Version),
    NoRelease,
    Failed(String),
}

fn parse_release(location: &str) -> Result<Option<Version>, String> {
    if location == RELEASES {
        return Ok(None);
    }
    let tag = location
        .strip_prefix(RELEASE_BASE)
        .ok_or("GitHub returned an unexpected release address.")?;
    let version = tag
        .strip_prefix('v')
        .and_then(|number| Version::parse(number).ok())
        .filter(|version| version.pre.is_empty() && version.build.is_empty())
        .ok_or("The latest release must use a vX.Y.Z tag.")?;
    Ok(Some(version))
}

pub async fn check_update() -> Result<Update, String> {
    // Use the same release endpoint as the installer. Read the redirect without following it.
    let mut command = Command::new("curl");
    command
        .args([
            "--disable",
            "--head",
            "--silent",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "10",
            "--max-time",
            "12",
            "--retry",
            "1",
            "--user-agent",
            concat!("Astroute/", env!("CARGO_PKG_VERSION")),
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}\n%{redirect_url}",
            LATEST_RELEASE,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let timed_out = "The update check timed out.";
    let output = timeout(Duration::from_secs(25), command.output())
        .await
        .map_err(|_| timed_out)?
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                "Install curl to check for updates.".into()
            } else {
                format!("Unable to start the update check: {error}")
            }
        })?;
    if !output.status.success() {
        return Err(match output.status.code() {
            Some(28) => timed_out.into(),
            Some(code) => format!("Unable to reach GitHub (curl error {code})."),
            None => "The update check was interrupted.".into(),
        });
    }
    let response = std::str::from_utf8(&output.stdout)
        .map_err(|_| "GitHub returned an invalid release response.")?;
    let (status, location) = response
        .split_once('\n')
        .ok_or("GitHub returned an invalid release response.")?;
    let version = match status {
        "301" | "302" | "303" | "307" | "308" => parse_release(location)?,
        "429" => return Err("GitHub's request limit was reached. Try again later.".into()),
        _ => return Err(format!("GitHub returned HTTP {status}.")),
    };
    let Some(version) = version else {
        return Ok(Update::NoRelease);
    };
    let current = Version::parse(VERSION).map_err(|error| error.to_string())?;
    if version.cmp_precedence(&current).is_gt() {
        Ok(Update::Available(version))
    } else {
        Ok(Update::Current)
    }
}

pub async fn open_release(version: Option<Version>) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let url = version.map_or_else(
            || RELEASES.into(),
            |version| format!("{RELEASE_BASE}v{version}"),
        );
        open::that_detached(url)
            .map_err(|error| format!("Unable to open the release page: {error}"))
    })
    .await
    .map_err(|error| error.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_tags_are_versions_with_safe_destinations() {
        let parse = |tag: &str| parse_release(&format!("{RELEASE_BASE}{tag}"));
        assert!(parse("v0.10.0").unwrap().unwrap() > Version::new(0, 9, 0));
        assert!(parse_release(RELEASES).unwrap().is_none());
        assert!(parse_release("https://github.com/another/project/releases/tag/v9.0.0").is_err());
        for tag in [
            "0.2.0",
            "v0.2.0-rc.1",
            "v0.2.0+build",
            "../other",
            "v0.2.0?x=1",
            "latest",
            "v0.2.0\n",
        ] {
            assert!(parse(tag).is_err());
        }
    }
}
