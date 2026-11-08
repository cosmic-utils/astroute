use crate::{Result, inventory::ip_json, linux, types::valid_interface};
use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr, path::Path};

pub const FAMILIES: [&str; 2] = ["-4", "-6"];
const TABLE: &str = "1095976018";
const PROTOCOL: &str = "243";
const SPECIFIC: u64 = 32764;
const PREFERRED: u64 = 32765;
const MAIN: u64 = 32766;
const METRIC: &str = "100";

fn number(value: &Value, expected: &str) -> bool {
    value.as_str() == Some(expected)
        || value
            .as_u64()
            .is_some_and(|value| expected.parse() == Ok(value))
}

fn preference_table(value: &Value) -> bool {
    number(value, TABLE)
}

fn unicast(route: &Value) -> bool {
    route.get("type").is_none_or(|kind| number(kind, "1"))
}

fn usable(route: &Value) -> bool {
    unicast(route)
        && route["dev"]
            .as_str()
            .is_some_and(|name| name != "lo" && valid_interface(name))
        && !route["flags"].as_array().is_some_and(|flags| {
            flags
                .iter()
                .any(|flag| flag == "linkdown" || flag == "dead")
        })
}

pub(crate) fn owned_route(route: &Value) -> bool {
    route["dst"] == "default"
        && unicast(route)
        && preference_table(&route["table"])
        && number(&route["protocol"], PROTOCOL)
        && number(&route["metric"], METRIC)
        && route["dev"].as_str().is_some_and(valid_interface)
}

fn plain_rule(rule: &Value) -> bool {
    rule["src"] == "all"
        && rule.as_object().is_some_and(|fields| {
            fields.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "priority" | "src" | "table" | "protocol" | "suppress_prefixlen"
                )
            })
        })
}

fn owned_rule(rule: &Value, priority: u64) -> bool {
    if rule["priority"] != priority || !plain_rule(rule) || !number(&rule["protocol"], PROTOCOL) {
        return false;
    }
    if priority == SPECIFIC {
        number(&rule["table"], "254") && rule["suppress_prefixlen"] == 0
    } else {
        preference_table(&rule["table"]) && rule.get("suppress_prefixlen").is_none()
    }
}

struct Routes {
    main: Vec<Value>,
    preferred: Vec<Value>,
    rules: Vec<Value>,
}

impl Routes {
    fn read(family: &str) -> Result<Self> {
        let mut main = Vec::new();
        let mut preferred = Vec::new();
        for route in ip_json(&["-N", family, "route", "show", "table", "all"])? {
            if preference_table(&route["table"]) {
                preferred.push(route);
            } else if route["dst"] == "default"
                && (route.get("table").is_none() || number(&route["table"], "254"))
            {
                main.push(route);
            }
        }
        main.sort_by_key(|route| route["metric"].as_u64().unwrap_or_default());
        Ok(Self {
            main,
            preferred,
            rules: ip_json(&["-N", family, "rule", "show"])?,
        })
    }

    fn has_rule(&self, priority: u64) -> bool {
        self.rules.iter().any(|rule| owned_rule(rule, priority))
    }

    fn can_set(&self) -> Result<()> {
        ensure!(
            self.preferred.len() <= 1 && self.preferred.iter().all(owned_route),
            "The default route table is already in use by another configuration"
        );
        ensure!(
            self.rules
                .iter()
                .filter(|rule| rule["priority"] == MAIN)
                .count()
                == 1
                && self.rules.iter().any(|rule| rule["priority"] == MAIN
                    && plain_rule(rule)
                    && number(&rule["table"], "254")
                    && rule.get("suppress_prefixlen").is_none()),
            "The system uses a custom main routing rule"
        );
        ensure!(
            self.rules.iter().all(|rule| {
                !matches!(rule["priority"].as_u64(), Some(SPECIFIC | PREFERRED))
                    || owned_rule(rule, SPECIFIC)
                    || owned_rule(rule, PREFERRED)
            }),
            "The default route priority is already in use by another configuration"
        );
        ensure!(
            self.rules
                .iter()
                .filter(|rule| preference_table(&rule["table"]))
                .all(|rule| owned_rule(rule, PREFERRED)),
            "Another routing rule uses the default route table"
        );
        ensure!(
            self.main.iter().all(unicast),
            "The system has a default route that blocks or redirects traffic"
        );
        ensure!(
            !self.has_rule(PREFERRED) || self.has_rule(SPECIFIC),
            "Restore Automatic before setting a new default route"
        );
        Ok(())
    }

    fn summary(&self) -> Value {
        let error = self.can_set().err().map(|error| error.to_string());
        let preferred = self.preferred.iter().find(|route| owned_route(route));
        let active = preferred
            .filter(|route| self.has_rule(SPECIFIC) && self.has_rule(PREFERRED) && usable(route));
        let current = active.or_else(|| self.main.first().filter(|route| usable(route)));
        let candidates: BTreeSet<_> = self
            .main
            .iter()
            .filter(|route| usable(route))
            .filter_map(|route| route["dev"].as_str())
            .collect();
        json!({"preferred": active.and_then(|route| route["dev"].as_str()),
            "current": current.and_then(|route| route["dev"].as_str()),
            "can_reset": preferred.is_some() || self.has_rule(SPECIFIC) || self.has_rule(PREFERRED),
            "candidates": candidates, "error": error})
    }
}

pub fn snapshot() -> [Value; 2] {
    FAMILIES.map(|family| {
        if family == "-6" && linux::ipv6_supported().is_ok_and(|supported| !supported) {
            return json!({});
        }
        match Routes::read(family) {
            Ok(routes) => routes.summary(),
            Err(error) => json!({"error": format!("Unable to read the default route: {error:#}")}),
        }
    })
}

fn rule(family: &str, verb: &str, priority: u64) -> Result<()> {
    let mut argv = linux::args(&[
        "/usr/bin/ip",
        family,
        "rule",
        verb,
        "priority",
        &priority.to_string(),
        "from",
        "all",
        "lookup",
        if priority == SPECIFIC { "main" } else { TABLE },
        "protocol",
        PROTOCOL,
    ]);
    if priority == SPECIFIC {
        argv.extend(linux::args(&["suppress_prefixlength", "0"]));
    }
    linux::command(&argv, None, true)?;
    Ok(())
}

fn route(family: &str, verb: &str, entry: &Value) -> Result<()> {
    let interface = entry["dev"]
        .as_str()
        .filter(|name| valid_interface(name))
        .context("Invalid interface in the default route")?;
    let mut argv = linux::args(&[
        "/usr/bin/ip",
        family,
        "route",
        verb,
        "default",
        "table",
        TABLE,
    ]);
    if let Some(gateway) = entry["gateway"].as_str() {
        let _: IpAddr = gateway.parse()?;
        argv.extend(linux::args(&["via", gateway]));
    }
    argv.extend(linux::args(&[
        "dev", interface, "metric", METRIC, "protocol", PROTOCOL,
    ]));
    if verb != "del" {
        if let Some(source) = entry["prefsrc"].as_str() {
            let _: IpAddr = source.parse()?;
            argv.extend(linux::args(&["src", source]));
        }
        if entry["gateway"].is_string() {
            argv.push("onlink".into());
        }
    }
    linux::command(&argv, None, true)?;
    Ok(())
}

pub fn set(family: &str, interface: Option<&str>) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Administrator access is required to change the system default route"
    );
    ensure!(FAMILIES.contains(&family), "Invalid IP family");
    let _lock = linux::lock(Path::new("/run/astroute-default-route.lock"), false)?;
    let state = Routes::read(family)?;
    let Some(interface) = interface else {
        for priority in [PREFERRED, SPECIFIC] {
            for _ in state
                .rules
                .iter()
                .filter(|entry| owned_rule(entry, priority))
            {
                rule(family, "del", priority)?;
            }
        }
        for entry in state.preferred.iter().filter(|entry| owned_route(entry)) {
            route(family, "del", entry)?;
        }
        return Ok(());
    };
    ensure!(
        interface != "lo" && valid_interface(interface),
        "Invalid network interface"
    );
    state.can_set()?;
    let selected = state
        .main
        .iter()
        .find(|entry| entry["dev"] == interface && usable(entry))
        .context("This interface no longer has a usable default route")?;
    let previous = state.preferred.first();
    route(
        family,
        if previous.is_some() { "replace" } else { "add" },
        selected,
    )?;
    let mut added = Vec::new();
    // Keep more-specific main routes before the preference, and leave earlier rules alone.
    for priority in [SPECIFIC, PREFERRED] {
        if !state.has_rule(priority) {
            if let Err(error) = rule(family, "add", priority) {
                let rollback = (|| -> Result<()> {
                    for priority in added.into_iter().rev() {
                        rule(family, "del", priority)?;
                    }
                    if let Some(previous) = previous {
                        route(family, "replace", previous)
                    } else {
                        route(family, "del", selected)
                    }
                })();
                if let Err(rollback) = rollback {
                    bail!(
                        "Unable to set the default route: {error:#}. Restore Automatic to finish cleanup: {rollback:#}"
                    );
                }
                return Err(error.context("Unable to set the default route"));
            }
            added.push(priority);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preference_respects_existing_policy_and_reserved_slots() {
        let mut routes = Routes {
            main: vec![json!({"dst": "default", "dev": "wlan0", "metric": 600})],
            preferred: Vec::new(),
            rules: vec![
                json!({"priority": 100, "src": "all", "fwmark": "0x4e000001", "table": "1308622849", "protocol": "242"}),
                json!({"priority": 12101, "src": "all", "fwmark": "0x2023", "table": "20230"}),
                json!({"priority": MAIN, "src": "all", "table": "254"}),
            ],
        };
        assert!(routes.can_set().is_ok());
        routes.rules.push(
            json!({"priority": SPECIFIC, "src": "all", "table": "254", "suppress_prefixlen": 0}),
        );
        assert!(routes.can_set().is_err());
        assert!(!routes.has_rule(SPECIFIC));
        routes.rules.pop();
        routes
            .main
            .push(json!({"type": "7", "dst": "default", "metric": 10}));
        assert!(routes.can_set().is_err());
    }
}
