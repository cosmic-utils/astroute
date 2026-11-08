#!/usr/bin/env bash
set -euo pipefail
repo=cosmic-utils/astroute
version=${1:-latest}
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# -le 1 ]] || fail 'Usage: install.sh [vVERSION]'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'Astroute packages currently support Linux x86_64.'
for command in curl sha256sum mktemp awk; do
    command -v "$command" >/dev/null || fail "Install $command first."
done
[[ -r /etc/os-release ]] || fail 'Cannot detect your Linux distribution.'
. /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
    *' arch '*) format=arch ;;
    *' ubuntu '*|*' pop '*|*' debian '*) format=deb ;;
    *' fedora '*) format=rpm ;;
    *) fail "Unsupported distribution: ${PRETTY_NAME:-unknown}. Build from source instead." ;;
esac
if command -v pgrep >/dev/null && { pgrep -x astroute >/dev/null || pgrep -x astroute-helper >/dev/null; }; then
    fail 'Quit Astroute and disable network controls before installing or updating.'
fi
fetch() { curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 15 --max-time 300 "$@"; }
if [[ $version == latest ]]; then
    release_url=$(fetch --head --output /dev/null --write-out '%{url_effective}' "https://github.com/$repo/releases/latest")
    version=${release_url##*/}
fi
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Select a release tag in vX.Y.Z format.'
number=${version#v}
case $format in
    deb) asset="astroute_${number}-1_amd64.deb" ;;
    rpm) asset="astroute-$number-1.x86_64.rpm" ;;
    arch) asset="astroute-$number-1-x86_64.pkg.tar.zst" ;;
esac
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
base="https://github.com/$repo/releases/download/$version"
printf 'Downloading Astroute %s for %s…\n' "$number" "${PRETTY_NAME:-$ID}"
fetch --output "$work/$asset" "$base/$asset"
fetch --output "$work/SHA256SUMS" "$base/SHA256SUMS"
awk -v asset="$asset" '$2 == asset { print; found++ } END { if (found != 1) exit 1 }' "$work/SHA256SUMS" > "$work/selected.sha256" || fail 'The release checksum is missing or ambiguous.'
(cd "$work" && sha256sum --check --strict --status selected.sha256) || fail 'Package checksum verification failed.'
# Let the package manager resolve dependencies and track every installed file.
root() {
    if (( EUID == 0 )); then "$@";
    else command -v sudo >/dev/null || fail 'Install sudo or run the installer as root.'; sudo -- "$@"; fi
}
case $format in
    deb) root apt-get install -y "$work/$asset" ;;
    arch) root pacman -U --noconfirm "$work/$asset" ;;
    rpm)
        if [[ -e /run/ostree-booted ]]; then
            root rpm-ostree install "$work/$asset"
            printf '%s\n' 'Reboot to finish installing Astroute.'
        else root dnf install -y "$work/$asset"; fi
        ;;
esac
printf '%s\n' 'Astroute installed. Open it from your application library.'
