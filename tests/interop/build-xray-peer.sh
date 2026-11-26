#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: build-xray-peer.sh work-directory" >&2
    exit 2
fi
mkdir -p -- "$1"
cd -- "$1"
curl -fsSL --retry 3 --max-time 90 \
    https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip \
    -o xray.zip
printf '%s  xray.zip\n' 0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978 | sha256sum -c >&2
unzip -qo xray.zip xray
printf '%s/xray\n' "$PWD"
