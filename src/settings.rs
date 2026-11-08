use reqwest::{Client, StatusCode};
use semver::Version;
use serde::Deserialize;
use std::time::Duration;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const RELEASE_API: &str = "https://api.github.com/repos/cosmic-utils/astroute/releases/latest";
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

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

fn parse_release(bytes: &[u8]) -> Result<Option<Release>, String> {
    let release: ApiRelease = serde_json::from_slice(bytes)
        .map_err(|_| "GitHub returned an invalid release response.".to_owned())?;
    if release.draft || release.prerelease {
        return Ok(None);
    }
    // Keep the browser destination within this repository's release pages.
    if release.tag_name.len() > 128
        || !release
            .tag_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte))
    {
        return Err("The latest release has an invalid version tag.".into());
    }
    let version = Version::parse(
        release
            .tag_name
            .strip_prefix('v')
            .unwrap_or(&release.tag_name),
    )
    .map_err(|_| "The latest release has an invalid version tag.".to_owned())?;
    if !version.pre.is_empty() {
        return Ok(None);
    }
    Ok(Some(Release {
        version,
        tag: release.tag_name,
    }))
}

pub async fn check_update() -> Result<Update, String> {
    let client = Client::builder()
        .user_agent(concat!("Astroute/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())?;
    let mut response = client
        .get(RELEASE_API)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .map_err(network_error)?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(Update::NoRelease);
    }
    if response.status() == StatusCode::TOO_MANY_REQUESTS
        || (response.status() == StatusCode::FORBIDDEN
            && response
                .headers()
                .get("x-ratelimit-remaining")
                .is_some_and(|value| value == "0"))
    {
        return Err("GitHub's request limit was reached. Try again later.".into());
    }
    response.error_for_status_ref().map_err(network_error)?;
    if !response.status().is_success() {
        return Err(format!("GitHub returned HTTP {}.", response.status()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(network_error)? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err("GitHub returned an oversized release response.".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let Some(release) = parse_release(&bytes)? else {
        return Ok(Update::NoRelease);
    };
    let current = Version::parse(VERSION).map_err(|error| error.to_string())?;
    if release.version.cmp_precedence(&current).is_gt() {
        Ok(Update::Available(release))
    } else {
        Ok(Update::Current)
    }
}

fn network_error(error: reqwest::Error) -> String {
    if error.is_timeout() {
        "The update check timed out. Try again.".into()
    } else {
        format!("Unable to check for updates: {error}")
    }
}

pub async fn open_release(release: Release) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        open::that_detached(format!("{RELEASE_BASE}{}", release.tag))
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
        let parse = |tag: &str| {
            parse_release(
                serde_json::json!({
                    "tag_name": tag, "draft": false, "prerelease": false,
                })
                .to_string()
                .as_bytes(),
            )
        };
        assert!(parse("v0.10.0").unwrap().unwrap().version > Version::new(0, 9, 0));
        assert!(parse("0.2.0").unwrap().is_some());
        assert!(parse("v0.2.0-rc.1").unwrap().is_none());
        for tag in ["../other", "v0.2.0?x=1", "latest", "v0.2.0\n"] {
            assert!(parse(tag).is_err());
        }
    }
}
