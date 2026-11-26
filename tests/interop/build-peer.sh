#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: build-peer.sh version work-directory" >&2
    exit 2
fi
version=$1
case "$version" in
    2.4.12) checksum=66952d9c95490e5875f04c9f8fa313b5e816d1b7b4d6cda3fb2ff749ad405dee ;;
    2.5.11) checksum=7e2672119bd4639819d560f332a8b9b7e28f562425c77899f36d419fe4265f56 ;;
    2.6.22) checksum=f46df740f05f86020137a41cfc8814352391cf861ed57f57b4e815cb97c1d2cf ;;
    2.6.23) checksum=4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96 ;;
    2.7.9) checksum=c42a6ed892ddfe2d6e3317a5040f19bec5827564affb2fe3f2b3904a94daacb1 ;;
    *) echo "Unknown OpenVPN reference version" >&2; exit 2 ;;
esac
mkdir -p -- "$2"
cd -- "$2"
archive="openvpn-$version.tar.gz"
curl -fsSL --retry 3 --max-time 60 "https://build.openvpn.net/downloads/releases/$archive" -o "$archive"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c >&2
fingerprint=F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7
keydir="$(mktemp -d)"
trap 'rm -rf -- "$keydir"' EXIT
curl -fsSL --retry 3 --max-time 60 "https://keys.openpgp.org/vks/v1/by-fingerprint/$fingerprint" -o "$keydir/key.asc"
curl -fsSL --retry 3 --max-time 60 "https://build.openvpn.net/downloads/releases/$archive.asc" -o "$keydir/archive.asc"
gpg --batch --homedir "$keydir" --import "$keydir/key.asc" >&2
gpg --batch --homedir "$keydir" --export "$fingerprint" > "$keydir/trusted.gpg"
test -s "$keydir/trusted.gpg"
gpgv --keyring "$keydir/trusted.gpg" "$keydir/archive.asc" "$archive" >&2
if [ "$version" = 2.4.12 ]; then
    # OpenVPN 2.4 predates OpenSSL 3. Build a private static dependency for
    # this disposable test executable. Nothing is installed on the host.
    ssl_source=openssl-1.1.1w
    ssl_sha=cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8
    ssl_prefix="$PWD/legacy-tls"
    curl -fsSL --retry 3 --max-time 60 \
        "https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1w/$ssl_source.tar.gz" -o "$ssl_source.tar.gz"
    printf '%s  %s\n' "$ssl_sha" "$ssl_source.tar.gz" | sha256sum -c >&2
    tar -xzf "$ssl_source.tar.gz"
    (
        cd "$ssl_source"
        ./config no-shared no-tests --prefix="$ssl_prefix" --libdir=lib
        make -j"${OPENVPN_BUILD_JOBS:-2}" build_libs
        make install_dev
    ) >&2
    export OPENSSL_CFLAGS="-I$ssl_prefix/include"
    export OPENSSL_LIBS="-L$ssl_prefix/lib -lssl -lcrypto -ldl -pthread"
fi
tar -xzf "$archive"
cd "openvpn-$version"
case "$version" in
    2.4.12)
        ./configure --enable-iproute2 --disable-lzo --disable-lz4 --disable-plugins >&2 ;;
    2.5.11)
        ./configure --disable-lzo --disable-lz4 --disable-plugins >&2 ;;
    *)
        ./configure --disable-dco --disable-plugin-auth-pam --disable-systemd >&2 ;;
esac
make -j"${OPENVPN_BUILD_JOBS:-2}" >&2
printf '%s/src/openvpn/openvpn\n' "$PWD"
