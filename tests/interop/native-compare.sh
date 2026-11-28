#!/usr/bin/env bash
set -euo pipefail
umask 077

if (( $# != 5 )); then
    echo 'Usage: native-compare.sh baseline candidate pinned-peer new-private-output max-loss-ppm' >&2
    exit 2
fi
baseline=$(realpath -- "$1")
candidate=$(realpath -- "$2")
peer=$(realpath -- "$3")
out=$(realpath -m -- "$4")
loss=$5
case "${OPENVPN_LOAD_NETWORK:-udp}" in
    udp|tcp) networks=("${OPENVPN_LOAD_NETWORK:-udp}") ;;
    both) networks=(udp tcp) ;;
    *) echo 'Invalid transport selection' >&2; exit 2 ;;
esac
case "${OPENVPN_LOAD_PACKETS:-mixed}" in
    64|256|1400|mixed) workloads=("${OPENVPN_LOAD_PACKETS:-mixed}") ;;
    all) workloads=(64 256 1400 mixed) ;;
    *) echo 'Invalid packet workload selection' >&2; exit 2 ;;
esac
case "${OPENVPN_LOAD_BACKEND:-direct}" in
    direct) export OPENVPN_LOAD_MANAGED=0 ;;
    managed) export OPENVPN_LOAD_MANAGED=1 ;;
    *) echo 'Invalid tunnel ownership mode' >&2; exit 2 ;;
esac
if [[ ! "$loss" =~ ^[0-9]{1,7}$ ]] || (( 10#$loss > 1000000 )); then
    echo 'Loss budget must be an integer between 0 and 1000000' >&2
    exit 2
fi
mkdir -- "$out"
export OPENVPN_LOAD_HARNESS="$candidate/tests/interop/native_load_test.go"

status=0
for network in "${networks[@]}"; do
    for workload in "${workloads[@]}"; do
        report="$out/$network-$workload"
        mkdir -- "$report"
        export OPENVPN_LOAD_NETWORK="$network" OPENVPN_LOAD_PACKETS="$workload"
        runner="$candidate/tests/interop/native-load.sh"
        if ! (cd "$baseline" && bash "$runner" "$peer" "$report/baseline"); then
            echo "Baseline workload failed: $network/$workload" | tee "$report/comparison.err" >&2
            status=1
            continue
        fi
        if ! (cd "$candidate" && bash "$runner" "$peer" "$report/candidate"); then
            echo "Candidate workload failed: $network/$workload" | tee "$report/comparison.err" >&2
            status=1
            continue
        fi
        if ! python3 "$candidate/tools/check_native_load.py" "$report/baseline" "$report/candidate" \
            --max-loss-ppm "$loss" > "$report/comparison.json" 2> "$report/comparison.err"; then
            cat "$report/comparison.err" >&2
            status=1
        fi
    done
done
exit "$status"
