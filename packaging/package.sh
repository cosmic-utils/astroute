#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
format=${1:?Usage: package.sh deb|rpm|arch [BINARY_DIRECTORY]}
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n1)
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Invalid package version' >&2; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo 'Release packages currently require x86_64' >&2; exit 1; }
out="$root/dist"
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
archive="astroute-$version-linux-x86_64.tar.gz"
if [[ $format != arch ]]; then
    "$root/packaging/stage.sh" "$work/stage" "${2:?Specify the release binary directory}"
    tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner -C "$work/stage" -czf "$out/$archive" usr
fi
case "$format" in
    deb)
        mkdir "$work/stage/DEBIAN"
        sed "s/@VERSION@/$version/g" "$root/packaging/debian/control.in" > "$work/stage/DEBIAN/control"
        install -m755 "$root/packaging/debian/postinst" "$work/stage/DEBIAN/postinst"
        dpkg-deb --root-owner-group --build "$work/stage" "$out/astroute_${version}-1_amd64.deb"
        ;;
    rpm)
        mkdir -p "$work/rpm/"{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
        cp "$out/$archive" "$work/rpm/SOURCES/"
        sed "s/@VERSION@/$version/g" "$root/packaging/rpm/astroute.spec.in" > "$work/rpm/SPECS/astroute.spec"
        rpmbuild --define "_topdir $work/rpm" --define '_build_id_links none' -bb "$work/rpm/SPECS/astroute.spec"
        cp "$work/rpm/RPMS/x86_64/astroute-$version-1.x86_64.rpm" "$out/"
        ;;
    arch)
        cp "$out/$archive" "$work/"
        checksum=$(sha256sum "$out/$archive" | cut -d' ' -f1)
        sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$checksum/g" "$root/packaging/arch/PKGBUILD.in" > "$work/PKGBUILD"
        (cd "$work" && PACKAGER="Astroute contributors <motixo@users.noreply.github.com>" makepkg --nodeps --nocheck --noconfirm)
        cp "$work/astroute-$version-1-x86_64.pkg.tar.zst" "$out/"
        ;;
    *) echo 'Choose deb, rpm or arch' >&2; exit 1 ;;
esac
