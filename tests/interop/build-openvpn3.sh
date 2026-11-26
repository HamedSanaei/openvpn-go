#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: build-openvpn3.sh work-directory" >&2
    exit 2
fi

# OpenVPN 3 Core release/3.11.8. Build the upstream CLI outside the project.
commit=4f3bdef73245d4ee9e8216c5d65baccc9568f6ef
archive_sha=522faf3f7485117423a9c398606062105c4453c11d4d5ebab45e7c209cc3a9ef
mkdir -p -- "$1"
cd -- "$1"
output=$PWD
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd -- "$work"
archive=openvpn3-$commit.tar.gz
curl -fsSL --retry 3 --max-time 90 \
    "https://codeload.github.com/OpenVPN/openvpn3/tar.gz/$commit" -o "$archive"
printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum -c >&2
tar -xzf "$archive"
cmake -S "openvpn3-$commit" -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DCLI_OVPNDCO=OFF >&2
cmake --build build --parallel "${OPENVPN3_BUILD_JOBS:-2}" --target ovpncli >&2
binary=$output/ovpncli
install -m 0755 build/test/ovpncli/ovpncli "$binary"
sha256sum "$binary" > "$output/ovpncli.sha256"
printf '%s\n' "$binary"
