use crate::{
    Result, linux,
    types::{Profile, Rule, valid_id, valid_proxy_id},
};
use anyhow::{bail, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::PathBuf};

pub struct Store {
    pub directory: PathBuf,
}
impl Store {
    pub fn user() -> Result<Self> {
        Ok(Self {
            directory: linux::config_home()?.join("cosmic-netguard"),
        })
    }
    fn read(&self, name: &str) -> Result<Value> {
        let path = self.directory.join(format!("{name}.json"));
        if !path.exists() {
            return Ok(json!({"version": 1}));
        }
        let value: Value = serde_json::from_str(&linux::read_limited(&path, 8 * 1024 * 1024)?)?;
        ensure!(
            value.is_object() && value["version"] == 1,
            "Unsupported {name} settings format"
        );
        Ok(value)
    }
    fn lock(&self, name: &str) -> Result<fs::File> {
        linux::private_dir(&self.directory)?;
        linux::lock(&self.directory.join(format!(".{name}.lock")), false)
    }
    fn write<T: serde::Serialize>(
        &self,
        name: &str,
        key: &str,
        items: &BTreeMap<String, T>,
    ) -> Result<()> {
        let value = json!({"version": 1, (key): items.values().collect::<Vec<_>>()});
        linux::atomic_write(
            &self.directory.join(format!("{name}.json")),
            &serde_json::to_vec_pretty(&value)?,
            0o600,
        )
    }
    fn items<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
        match value.get(key) {
            None => Ok(&[]),
            Some(Value::Array(items)) => Ok(items),
            _ => bail!("Invalid {key} settings"),
        }
    }
    pub fn profiles(&self) -> Result<BTreeMap<String, Profile>> {
        let value = self.read("proxies")?;
        let mut profiles = BTreeMap::new();
        for raw in Self::items(&value, "profiles")? {
            ensure!(raw["id"].as_str().is_some(), "Invalid saved proxy profile");
            let p = Profile::parse(raw, None)?;
            profiles.insert(p.id.clone(), p);
        }
        Ok(profiles)
    }
    pub fn profile(&self, id: &str) -> Result<Profile> {
        self.profiles()?.remove(id).ok_or_else(|| anyhow::anyhow!("The proxy profile is missing from your settings. Select another proxy or save the profile again."))
    }
    pub fn rules(&self) -> Result<BTreeMap<String, Rule>> {
        let value = self.read("rules")?;
        let mut rules = BTreeMap::new();
        for raw in Self::items(&value, "rules")? {
            let r = Rule::parse(raw)?;
            rules.insert(r.policy.app_id.clone(), r);
        }
        Ok(rules)
    }
    pub fn save_profile(&self, raw: &Value) -> Result<Profile> {
        let _lock = self.lock("proxies")?;
        let mut profiles = self.profiles()?;
        let mut p = Profile::parse(raw, raw["id"].as_str().and_then(|id| profiles.get(id)))?;
        p.revision = uuid::Uuid::new_v4().to_string();
        ensure!(
            profiles.contains_key(&p.id) || profiles.len() < 100,
            "At most 100 proxy profiles are supported"
        );
        profiles.insert(p.id.clone(), p.clone());
        self.write("proxies", "profiles", &profiles)?;
        Ok(p)
    }
    pub fn save_rule(&self, raw: &Value) -> Result<Rule> {
        let rule = Rule::parse(raw)?;
        let _lock = self.lock("rules")?;
        let mut rules = self.rules()?;
        ensure!(
            rules.contains_key(&rule.policy.app_id) || rules.len() < 1000,
            "At most 1000 application rules are supported"
        );
        rules.insert(rule.policy.app_id.clone(), rule.clone());
        self.write("rules", "rules", &rules)?;
        Ok(rule)
    }
    pub fn remove(&self, name: &str, id: &str) -> Result<()> {
        if name == "proxies" {
            ensure!(valid_proxy_id(id), "Invalid proxy ID");
            let _lock = self.lock(name)?;
            let mut p = self.profiles()?;
            p.remove(id);
            self.write(name, "profiles", &p)
        } else if name == "rules" {
            ensure!(valid_id(id, 241), "Invalid application ID");
            let _lock = self.lock(name)?;
            let mut r = self.rules()?;
            r.remove(id);
            self.write(name, "rules", &r)
        } else {
            bail!("Unknown settings catalog")
        }
    }
}
