use anyhow::{Context, bail};
use astroute_backend::{Result, client, daemon, proxy, system_route};
use serde_json::json;
use std::io::Write;
fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.first().is_some_and(|s| s == "--client") {
        let result = client::run(&arguments[1..]);
        let failed = result.is_err();
        let response = match result {
            Ok(data) => json!({"ok":true,"data":data}),
            Err(error) => json!({"ok":false,"error":format!("{error:#}")}),
        };
        let mut output = std::io::stdout().lock();
        let _ = serde_json::to_writer(&mut output, &response);
        let _ = output.write_all(b"\n");
        drop(output);
        if failed {
            std::process::exit(1);
        }
        return;
    }
    let result = (|| -> Result<()> {
        if arguments == ["--proxy-worker"] {
            return proxy::worker();
        }
        if arguments
            .first()
            .is_some_and(|argument| argument == "--system-route")
        {
            return match arguments.as_slice() {
                [_, family] => system_route::set(family, None),
                [_, family, interface] => system_route::set(family, Some(interface)),
                _ => bail!("Invalid system default route arguments"),
            };
        }
        if arguments.len() == 3 && arguments[0] == "--cleanup" && arguments[1] == "--uid" {
            return daemon::cleanup(arguments[2].parse().context("Invalid user ID")?);
        }
        let uid = if arguments.is_empty() {
            std::env::var("PKEXEC_UID")
                .unwrap_or_default()
                .parse()
                .context("Specify the desktop user's UID")?
        } else if arguments.len() == 2 && arguments[0] == "--uid" {
            arguments[1].parse().context("Invalid user ID")?
        } else {
            bail!(
                "Usage: astroute-helper [--uid UID | --cleanup --uid UID | --client COMMAND | --proxy-worker]"
            );
        };
        daemon::serve(uid)
    })();
    if let Err(error) = result {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
