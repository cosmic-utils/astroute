#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
stage=${1:?Usage: stage.sh DESTDIR BINARY_DIRECTORY}
binaries=${2:?Specify the release binary directory}
install -Dm755 "$binaries/astroute" "$stage/usr/bin/astroute"
install -Dm755 "$binaries/astroute-helper" "$stage/usr/libexec/astroute-helper"
app_id=io.github.astroute.Astroute
for entry in "applications/$app_id.desktop" "metainfo/$app_id.metainfo.xml" "polkit-1/actions/$app_id.policy"; do
    install -Dm644 "$root/resources/${entry##*/}" "$stage/usr/share/$entry"
done
while IFS= read -r -d '' icon; do
    install -Dm644 "$icon" "$stage/usr/share/icons/${icon#"$root/resources/icons/"}"
done < <(find "$root/resources/icons/hicolor" -type f -name '*.svg' -print0)
install -Dm644 "$root/LICENSE" "$stage/usr/share/licenses/astroute/LICENSE"
install -Dm644 "$root/README.md" "$stage/usr/share/doc/astroute/README.md"
