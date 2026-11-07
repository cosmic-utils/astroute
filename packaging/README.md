# Release packages

Version comes from `Cargo.toml`. Tag the matching commit `vX.Y.Z` and push the tag;
GitHub Actions builds and publishes native packages with `SHA256SUMS` and `install.sh`.
The workflow builds without running tests or launching Astroute.

Build Debian and RPM packages locally in Docker:

```sh
docker build -f packaging/Containerfile -t astroute-builder .
docker run --rm -v "$PWD:/source" -e CARGO_TARGET_DIR=/source/target/distribution astroute-builder bash -euc '
  cargo build --release --workspace --locked
  packaging/package.sh deb target/distribution/release
  packaging/package.sh rpm target/distribution/release
'
```

On Arch, run `packaging/package.sh arch` as a regular user after creating the portable
archive in `dist`. It generates a PKGBUILD with the archive's checksum and uses `makepkg`.
Output packages install into `/usr`; files and dependencies remain owned by the package manager.
The portable archive is a packaging input, not a standalone installer.

Before tagging, update both Cargo package versions, `Cargo.lock`, AppStream release metadata
and the short release notes. Binary packages support x86_64. The build image uses Ubuntu
22.04 and Rust 1.93.1 so the binaries do not inherit a rolling distribution's newer glibc.
