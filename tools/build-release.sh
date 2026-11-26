#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ] || [ "$1" != v0.1.0-beta ]; then
    echo "Usage: build-release.sh v0.1.0-beta GOOS GOARCH output-directory" >&2
    exit 2
fi
version=$1
system=$2
arch=$3
case "$system/$arch" in
    linux/amd64|linux/arm64|windows/amd64|darwin/arm64) ;;
    *) echo "Unsupported release target" >&2; exit 2 ;;
esac
output=$4
export GOWORK=off
export GOFLAGS=
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
[[ "$epoch" =~ ^[0-9]+$ ]]

python3 tools/release_audit.py --check docs/sbom.spdx.json >&2
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
name="openvpn-go-$version-$system-$arch"
stage="$work/$name"
mkdir -p "$output" "$stage/licenses"
suffix=
if [ "$system" = windows ]; then suffix=.exe; fi
build() {
    CGO_ENABLED=0 GOOS="$system" GOARCH="$arch" go build -mod=readonly -trimpath \
        -buildvcs=false -ldflags='-buildid=' -o "$stage/$1$suffix" "./cmd/$1"
}
build ovpn-inspect
if [ "$system" = linux ]; then build ovpn-xray; fi

copy_text() { sed 's/\r$//' "$1" > "$2"; }
copy_text LICENSE "$stage/LICENSE"
copy_text CHANGELOG.md "$stage/CHANGELOG.md"
copy_text docs/sbom.spdx.json "$stage/sbom.spdx.json"
copy_text "$(go env GOROOT)/LICENSE" "$stage/licenses/Go.LICENSE"
for namepart in crypto sys; do
    moddir=$(go list -m -f '{{.Dir}}' "golang.org/x/$namepart")
    copy_text "$moddir/LICENSE" "$stage/licenses/x-$namepart.LICENSE"
    if [ -f "$moddir/PATENTS" ]; then
        copy_text "$moddir/PATENTS" "$stage/licenses/x-$namepart.PATENTS"
    fi
done
printf '%s\n' "$version" > "$stage/VERSION"
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$work" -cf - "$name" \
    | gzip -n > "$work/$name.tar.gz"
mv -- "$work/$name.tar.gz" "$output/$name.tar.gz"
printf '%s/%s.tar.gz\n' "$output" "$name"
