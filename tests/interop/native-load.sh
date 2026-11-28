#!/usr/bin/env bash
set -euo pipefail
umask 077

# Run from the root of a Linux checkout. The output directory must be new.
if [ "$#" -ne 2 ] || [ ! -f go.mod ]; then
    echo 'Usage from checkout root: native-load.sh pinned-community-binary new-private-directory' >&2
    exit 2
fi
peer=$(realpath -- "$1")
out=$(realpath -m -- "$2")
case "$out/" in "$(pwd -P)/"*) echo 'Use an output directory outside the checkout' >&2; exit 2 ;; esac
test -x "$peer"
mkdir -- "$out"
export CGO_ENABLED=0 GOTOOLCHAIN=local LC_ALL=C
harness=$(realpath -- "${OPENVPN_LOAD_HARNESS:-tests/interop/native_load_test.go}")
constraints=$(realpath -- "$(dirname -- "${BASH_SOURCE[0]}")/../../tools/native_load_constraints.py")
cat > "$out/peer-wrapper" <<'SH'
#!/bin/sh
set -eu
printf '%s\n' "$$" > "$OPENVPN_LOAD_JSON.peer-pid"
exec "$OPENVPN_INTEROP_BIN" "$@"
SH
chmod 700 "$out/peer-wrapper"
python3 - "$(pwd -P)/tests/interop/native_load_test.go" "$harness" "$out/overlay.json" <<'PY'
import json
import sys

with open(sys.argv[3], "x") as stream:
    json.dump({"Replace": {sys.argv[1]: sys.argv[2]}}, stream)
PY
go test -overlay "$out/overlay.json" -c -o "$out/interop.test" ./tests/interop

# The report records only the environment required to compare samples.
python3 - "$peer" "$harness" "$out/environment.json" <<'PY'
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys

def run(*args):
    return subprocess.check_output(args, text=True).strip()

peer = pathlib.Path(sys.argv[1])
harness = pathlib.Path(sys.argv[2])
cpu = run("lscpu")
topology = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in cpu.splitlines()
            if line.split(":", 1)[0] in {"Model name", "Socket(s)", "Core(s) per socket", "Thread(s) per core"}}
settings = {"schema": 2, "commit": run("git", "rev-parse", "HEAD"), "dirty": bool(run("git", "status", "--porcelain")),
            "system": {"kernel": platform.release(), "arch": platform.machine(), "cpu": topology,
                       "affinity": sorted(os.sched_getaffinity(0)), "go": run("go", "version"),
                       "peer_sha256": hashlib.sha256(peer.read_bytes()).hexdigest(),
                       "harness_sha256": hashlib.sha256(harness.read_bytes()).hexdigest(),
                       "peer_version": run(str(peer), "--version").splitlines()[0],
                       "profiled": os.environ.get("OPENVPN_LOAD_PROFILE", "0") == "1",
                       "gomaxprocs": os.environ.get("GOMAXPROCS", "auto"),
                       "governors": sorted({path.read_text().strip() for path in
                                            pathlib.Path("/sys/devices/system/cpu").glob("cpu*/cpufreq/scaling_governor")})}}
with open(sys.argv[3], "x") as stream:
    json.dump(settings, stream, indent=2)
PY

args=(-test.v -test.run '^TestNativeLoad$' -test.timeout=0)
if [ "${OPENVPN_LOAD_PROFILE:-0}" = 1 ]; then
    args+=(-test.cpuprofile="$out/cpu.pprof" -test.memprofile="$out/heap.pprof"
           -test.mutexprofile="$out/mutex.pprof" -test.blockprofile="$out/block.pprof")
fi
env_args=("OPENVPN_INTEROP_BIN=$peer" OPENVPN_NATIVE_LOAD=1 "OPENVPN_LOAD_JSON=$out/metrics.jsonl"
          "OPENVPN_LOAD_CONSTRAINTS=$constraints" "OPENVPN_LOAD_PEER_WRAPPER=$out/peer-wrapper")
for key in OPENVPN_LOAD_NETWORK OPENVPN_LOAD_PACKETS OPENVPN_LOAD_SESSIONS OPENVPN_LOAD_WINDOWS \
           OPENVPN_LOAD_SECONDS OPENVPN_LOAD_WARMUP OPENVPN_LOAD_BATCH OPENVPN_LOAD_RESTART_EVERY OPENVPN_LOAD_REKEY OPENVPN_LOAD_PAUSE_US \
           OPENVPN_LOAD_MANAGED OPENVPN_INTEROP_VERSION GOMAXPROCS; do
    if [ -n "${!key:-}" ]; then env_args+=("$key=${!key}"); fi
done

# PID and network namespaces terminate the children and discard all routing
# changes even if the driver is interrupted. Keep output readable by the caller.
trap 'sudo -n chown --no-dereference "$(id -u):$(id -g)" -- "$out"/*' EXIT
sudo -n env "${env_args[@]}" unshare --net --pid --fork --kill-child --mount-proc sh -c '
    umask 077
    ip link set lo up
    exec "$@"
' sh "$out/interop.test" "${args[@]}" > "$out/test.log" 2>&1
