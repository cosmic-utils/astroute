- Added Settings for startup at login, update checks and the installed version.
- Update checks retry temporary failures and offer a link to GitHub Releases if the check fails.

Download the `.deb` for Pop!_OS/Ubuntu, `.pkg.tar.zst` for Arch, or `.rpm` for Fedora.
The installer selects the package and verifies its SHA-256 checksum:

```sh
curl -fsSL https://raw.githubusercontent.com/cosmic-utils/astroute/main/install.sh | bash
```

Linux x86_64 only. Quit Astroute before updating.
