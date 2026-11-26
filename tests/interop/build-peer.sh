#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: build-peer.sh version work-directory" >&2
    exit 2
fi
version=$1
case "$version" in
    2.6.22) checksum=f46df740f05f86020137a41cfc8814352391cf861ed57f57b4e815cb97c1d2cf ;;
    2.6.23) checksum=4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96 ;;
    *) echo "Unknown OpenVPN reference version" >&2; exit 2 ;;
esac
mkdir -p -- "$2"
cd -- "$2"
archive="openvpn-$version.tar.gz"
curl -fsSL --retry 3 --max-time 60 "https://build.openvpn.net/downloads/releases/$archive" -o "$archive"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c >&2
tar -xzf "$archive"
cd "openvpn-$version"
./configure --disable-dco --disable-plugin-auth-pam --disable-systemd >&2
make -j"${OPENVPN_BUILD_JOBS:-2}" >&2
printf '%s/src/openvpn/openvpn\n' "$PWD"
