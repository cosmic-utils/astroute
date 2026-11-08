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
    Available(Release),
    NoRelease,
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct Release {
    pub version: Version,
    tag: String,
}

fn parse_release(location: &str) -> Result<Option<Release>, String> {
    if location == RELEASES {
        return Ok(None);
    }
    let tag = location
        .strip_prefix(RELEASE_BASE)
        .ok_or("GitHub returned an unexpected release address.")?;
    let version = Version::parse(tag.strip_prefix('v').unwrap_or(tag))
        .map_err(|_| "The latest release has an invalid version tag.")?;
    if !version.pre.is_empty() {
        return Ok(None);
    }
    Ok(Some(Release {
        version,
        tag: tag.to_owned(),
    }))
}

pub async fn check_update() -> Result<Update, String> {
    // Use the same release endpoint as the installer. Read the redirect without following it.
    let mut command = Command::new("curl");
    command
        .args([
            "--disable",
            "--head",
            "--silent",
            "--show-error",
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
        if output.status.code() == Some(28) {
            return Err(timed_out.into());
        }
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Unable to reach GitHub. {}", detail.trim())
            .trim_end()
            .into());
    }
    let response = std::str::from_utf8(&output.stdout)
        .map_err(|_| "GitHub returned an invalid release response.")?;
    let (status, location) = response
        .split_once('\n')
        .ok_or("GitHub returned an invalid release response.")?;
    let release = match status {
        "301" | "302" | "303" | "307" | "308" => parse_release(location)?,
        "404" => None,
        "429" => return Err("GitHub's request limit was reached. Try again later.".into()),
        _ => return Err(format!("GitHub returned HTTP {status}.")),
    };
    let Some(release) = release else {
        return Ok(Update::NoRelease);
    };
    let current = Version::parse(VERSION).map_err(|error| error.to_string())?;
    if release.version.cmp_precedence(&current).is_gt() {
        Ok(Update::Available(release))
    } else {
        Ok(Update::Current)
    }
}

pub async fn open_release(release: Option<Release>) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        let url = release.map_or_else(
            || RELEASES.into(),
            |release| format!("{RELEASE_BASE}{}", release.tag),
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
        assert!(parse("v0.10.0").unwrap().unwrap().version > Version::new(0, 9, 0));
        assert!(parse("0.2.0").unwrap().is_some());
        assert!(parse("v0.2.0-rc.1").unwrap().is_none());
        assert!(parse_release(RELEASES).unwrap().is_none());
        assert!(parse_release("https://github.com/another/project/releases/tag/v9.0.0").is_err());
        for tag in ["../other", "v0.2.0?x=1", "latest", "v0.2.0\n"] {
            assert!(parse(tag).is_err());
        }
    }
}
