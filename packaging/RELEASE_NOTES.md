Native per-application network controls for COSMIC.

- Allow, block or limit apps to the local network.
- Choose Wi-Fi, Ethernet or VPN routing and SOCKS5/HTTP(S) proxies.
- Save rules without root and manage controls from the system tray.

Download the `.deb` for Pop!_OS/Ubuntu, `.pkg.tar.zst` for Arch, or `.rpm` for Fedora.
The installer selects the package and verifies its SHA-256 checksum:

```sh
curl -fsSL https://raw.githubusercontent.com/cosmic-utils/astroute/main/install.sh | bash
```

Linux x86_64 only. Quit existing app processes and relaunch through Astroute or its managed
app-library entries to protect connections from startup. Direct and alternate launches
are discovered after startup. This initial release has build and static-check validation;
application, networking and installer scenarios have not been executed.
