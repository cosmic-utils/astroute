use anyhow::{Context, Result, bail, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
};
const ASSETS: &[(&str, &[u8])] = &[
    (
        "share/applications/io.github.astroute.Astroute.desktop",
        include_bytes!("../../../../resources/io.github.astroute.Astroute.desktop"),
    ),
    (
        "share/metainfo/io.github.astroute.Astroute.metainfo.xml",
        include_bytes!("../../../../resources/io.github.astroute.Astroute.metainfo.xml"),
    ),
    (
        "share/polkit-1/actions/io.github.astroute.Astroute.policy",
        include_bytes!("../../../../resources/io.github.astroute.Astroute.policy"),
    ),
    (
        "share/icons/hicolor/scalable/apps/io.github.astroute.Astroute.svg",
        include_bytes!(
            "../../../../resources/icons/hicolor/scalable/apps/io.github.astroute.Astroute.svg"
        ),
    ),
    (
        "share/icons/hicolor/scalable/apps/io.github.astroute.Astroute-symbolic.svg",
        include_bytes!(
            "../../../../resources/icons/hicolor/scalable/apps/io.github.astroute.Astroute-symbolic.svg"
        ),
    ),
    (
        "share/icons/hicolor/16x16/apps/io.github.astroute.Astroute-symbolic.svg",
        include_bytes!(
            "../../../../resources/icons/hicolor/16x16/apps/io.github.astroute.Astroute-symbolic.svg"
        ),
    ),
];
fn install() -> Result<()> {
    let mut destdir = PathBuf::from("/");
    let mut uninstall = false;
    let mut arguments = std::env::args().skip(1);
    while let Some(arg) = arguments.next() {
        match arg.as_str() {
            "--prefix" => ensure!(
                arguments.next().as_deref() == Some("/usr"),
                "Only /usr is supported"
            ),
            "--destdir" => {
                let value = arguments.next().context("Missing destination directory")?;
                if !value.is_empty() {
                    destdir = PathBuf::from(value);
                }
            }
            "--uninstall" => uninstall = true,
            _ => bail!("Usage: astroute-install [--prefix /usr] [--destdir DIR] [--uninstall]"),
        }
    }
    let base = destdir.join("usr");
    let current = std::env::current_exe()?;
    let binaries = current.parent().context("Missing executable directory")?;
    let files = [
        (binaries.join("astroute"), "bin/astroute"),
        (binaries.join("astroute-helper"), "libexec/astroute-helper"),
        (current.clone(), "libexec/astroute-install"),
    ];
    // Read every binary before changing an installation, including the installer itself.
    let contents = if uninstall {
        Vec::new()
    } else {
        files
            .iter()
            .map(|(source, _)| {
                fs::read(source)
                    .with_context(|| format!("Missing build artifact: {}", source.display()))
            })
            .collect::<Result<Vec<_>>>()?
    };
    for (index, (_, relative)) in files.iter().enumerate() {
        let target = base.join(relative);
        if uninstall {
            remove(&target)?;
        } else {
            fs::create_dir_all(target.parent().unwrap())?;
            astroute_backend::linux::atomic_write(&target, &contents[index], 0o755)?;
        }
    }
    for (relative, bytes) in ASSETS {
        let target = base.join(relative);
        if uninstall {
            remove(&target)?;
        } else {
            fs::create_dir_all(target.parent().unwrap())?;
            astroute_backend::linux::atomic_write(&target, bytes, 0o644)?;
        }
    }
    println!(
        "{}",
        if uninstall {
            "Astroute uninstalled"
        } else {
            "Astroute installed"
        }
    );
    Ok(())
}
fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn main() {
    if let Err(error) = install() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
