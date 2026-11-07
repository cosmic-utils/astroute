name := 'astroute'
appid := 'io.github.astroute.Astroute'
prefix := '/usr'
rootdir := ''

default: build-release

build-debug:
    cargo build --workspace --locked

build-release:
    cargo build --release --workspace --locked

run:
    cargo run --locked -p astroute

check:
    cargo fmt --all --check
    cargo clippy --workspace --locked -- -D warnings

test:
    cargo test --workspace --locked

test-network:
    cargo build --release --locked -p astroute-backend --bin astroute-helper --example network-integration
    sudo unshare --mount --net -- ./target/release/examples/network-integration

install:
    ./target/release/astroute-install --prefix '{{prefix}}' --destdir '{{rootdir}}'

uninstall:
    ./target/release/astroute-install --prefix '{{prefix}}' --destdir '{{rootdir}}' --uninstall

package format:
    packaging/package.sh {{format}} target/release
