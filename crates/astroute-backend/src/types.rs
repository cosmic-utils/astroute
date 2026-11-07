use crate::Result;
use anyhow::{bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::IpAddr;

pub fn valid_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .as_bytes()
            .first()
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.+-".contains(&c))
}
pub fn valid_proxy_id(value: &str) -> bool {
    valid_id(value, 81)
        && value
            .as_bytes()
            .first()
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
}
pub fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:@+-".contains(&c))
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Allow,
    Block,
    Local,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fallback {
    #[default]
    Block,
    Direct,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub app_id: String,
    #[serde(default)]
    pub mode: Mode,
    pub interface: Option<String>,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_fallback: Fallback,
}
impl Policy {
    pub fn parse(raw: &Value) -> Result<Self> {
        let mut value = raw.clone();
        ensure!(value.is_object(), "Invalid application rule");
        for key in ["interface", "proxy"] {
            if value[key] == "" {
                value[key] = Value::Null;
            }
        }
        let policy: Self = serde_json::from_value(value)?;
        ensure!(valid_id(&policy.app_id, 241), "Invalid application ID");
        if let Some(interface) = &policy.interface {
            ensure!(
                valid_interface(interface) && interface != "lo",
                "Select a valid network interface other than loopback"
            );
        }
        if let Some(proxy) = &policy.proxy {
            ensure!(valid_proxy_id(proxy), "Invalid proxy ID");
        }
        Ok(policy)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(flatten)]
    pub policy: Policy,
}
impl Rule {
    pub fn parse(raw: &Value) -> Result<Self> {
        Ok(Self {
            policy: Policy::parse(raw)?,
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub revision: String,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}
impl Profile {
    pub fn parse(raw: &Value, previous: Option<&Self>) -> Result<Self> {
        ensure!(raw.is_object(), "Invalid proxy profile");
        let text = |key: &str, default: &str| -> Result<String> {
            match raw.get(key) {
                None => Ok(default.into()),
                Some(value) => Ok(value
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid proxy {key}"))?
                    .into()),
            }
        };
        let id = match raw.get("id") {
            None | Some(Value::Null) => format!("proxy-{}", uuid::Uuid::new_v4().simple()),
            Some(v) => v
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid proxy ID"))?
                .to_owned(),
        };
        ensure!(valid_proxy_id(&id), "Invalid proxy ID");
        let revision = text("revision", "00000000-0000-0000-0000-000000000000")?;
        let revision = uuid::Uuid::parse_str(&revision)
            .map_err(|_| anyhow::anyhow!("Invalid proxy revision"))?
            .to_string();
        let name = text("name", "")?;
        ensure!(
            (1..=80).contains(&name.trim().chars().count()) && !name.chars().any(|c| c < ' '),
            "Enter a proxy name (1–80 characters)"
        );
        let protocol = text("protocol", "socks5")?;
        ensure!(
            ["socks5", "http", "https"].contains(&protocol.as_str()),
            "Unsupported proxy protocol"
        );
        let port = raw["port"]
            .as_u64()
            .filter(|p| (1..=65535).contains(p))
            .ok_or_else(|| anyhow::anyhow!("Proxy port must be between 1 and 65535"))?
            as u16;
        let mut host = text("host", "")?.trim().to_owned();
        if host.starts_with('[') && host.ends_with(']') {
            host = host[1..host.len() - 1].into();
        }
        ensure!(
            !host.is_empty() && host.len() <= 253,
            "Enter a proxy hostname or IP address"
        );
        if let Ok(ip) = host.parse::<IpAddr>() {
            host = ip.to_string();
        } else {
            host = idna::domain_to_ascii(&host)
                .map_err(|_| anyhow::anyhow!("Invalid proxy hostname"))?;
            ensure!(
                host.len() <= 253
                    && host.trim_end_matches('.').split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && label.as_bytes()[0].is_ascii_alphanumeric()
                            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                            && label
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    }),
                "Enter a hostname without a scheme, path or port"
            );
        }
        let username = text("username", "")?;
        let mut password = match raw.get("password") {
            None | Some(Value::Null) => previous
                .filter(|p| p.username == username)
                .map(|p| p.password.clone())
                .unwrap_or_default(),
            Some(value) => value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid proxy credentials"))?
                .into(),
        };
        if username.is_empty() {
            password.clear();
        }
        ensure!(
            !username.contains(':')
                && !username
                    .chars()
                    .chain(password.chars())
                    .any(|c| c < ' ' || c == '\u{7f}'),
            "Invalid characters in proxy credentials"
        );
        ensure!(
            username.len() <= 255 && password.len() <= 255,
            "Proxy credentials must be at most 255 bytes"
        );
        if protocol == "socks5" && !username.is_empty() && password.is_empty() {
            bail!("SOCKS5 authentication needs a username and password");
        }
        Ok(Self {
            id,
            revision,
            name: name.trim().into(),
            protocol,
            host,
            port,
            username,
            password,
        })
    }
    pub fn public(&self) -> Value {
        json!({"id": self.id, "revision": self.revision, "name": self.name, "protocol": self.protocol, "host": self.host, "port": self.port, "username": self.username, "has_password": !self.password.is_empty()})
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Application {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub argv: Vec<String>,
    pub path: String,
    pub working_dir: String,
    pub controllable: bool,
    pub reason: String,
    pub managed_launcher: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Process {
    pub pid: u32,
    pub uid: u32,
    pub name: String,
    pub exe: String,
    pub cgroup: String,
    pub argv: Vec<String>,
}
#[derive(Clone)]
pub struct Entry {
    pub policy: Policy,
    pub cgroup: String,
    pub proxy_port: Option<u16>,
    pub dns_port: Option<u16>,
}
