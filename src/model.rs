use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    pub enabled: bool,
    pub apps: Vec<Application>,
    pub interfaces: Vec<Interface>,
    pub connections: Vec<Connection>,
    pub policies: Vec<Policy>,
    pub pending_rules: Vec<String>,
    pub proxies: Vec<ProxyProfile>,
    pub active: Vec<ActiveGroup>,
    pub events: Vec<Event>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Application {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub argv: Vec<String>,
    pub controllable: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Policy {
    pub app_id: String,
    pub mode: String,
    pub interface: Option<String>,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub proxy_fallback: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ProxyProfile {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub has_password: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProxyTestResult {
    pub elapsed_ms: u64,
    pub target: String,
}

pub struct ProxyEditor {
    pub id: Option<String>,
    pub name: String,
    pub protocol: usize,
    pub host: String,
    pub port: String,
    pub username: String,
    pub password: String,
    pub has_password: bool,
}

impl Default for ProxyEditor {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            protocol: 0,
            host: String::new(),
            port: "1080".into(),
            username: String::new(),
            password: String::new(),
            has_password: false,
        }
    }
}

impl From<&ProxyProfile> for ProxyEditor {
    fn from(profile: &ProxyProfile) -> Self {
        Self {
            id: Some(profile.id.clone()),
            name: profile.name.clone(),
            protocol: match profile.protocol.as_str() {
                "http" => 1,
                "https" => 2,
                _ => 0,
            },
            host: profile.host.clone(),
            port: profile.port.to_string(),
            username: profile.username.clone(),
            password: String::new(),
            has_password: profile.has_password,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Interface {
    pub name: String,
    pub kind: String,
    pub up: bool,
    pub default: bool,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Connection {
    pub pid: u32,
    pub name: String,
    pub exe: String,
    pub protocol: String,
    pub state: String,
    pub remote: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ActiveGroup {
    pub app_id: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Event {
    pub time: String,
    pub text: String,
}
