#!/usr/bin/env sh
set -eu

duration=${FUZZ_TIME:-5s}
parallel=${FUZZ_PARALLEL:-2}
target=${1:-all}

run() {
    if [ "$target" = all ] || [ "$target" = "$2" ]; then
        go test "$1" -run '^$' -fuzz "^$2$" -fuzztime "$duration" -parallel "$parallel"
    fi
}

case "$target" in
    all|FuzzProfile|FuzzTCPFrame|FuzzControlPacket|FuzzProtectedControl|FuzzDataPacket|FuzzControlPush) ;;
    *) echo "Unknown fuzz target" >&2; exit 2 ;;
esac

run ./profile FuzzProfile
run ./transport FuzzTCPFrame
run ./internal/wire FuzzControlPacket
run ./internal/control FuzzProtectedControl
run ./internal/data FuzzDataPacket
run ./internal/tlscontrol FuzzControlPush
