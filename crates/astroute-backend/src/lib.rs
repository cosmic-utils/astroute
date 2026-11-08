pub mod autostart;
pub mod client;
pub mod daemon;
pub mod dns;
pub mod inventory;
pub mod kernel;
pub mod launcher;
pub mod linux;
pub mod proxy;
pub mod scopes;
pub mod store;
pub mod types;

pub type Result<T> = anyhow::Result<T>;
