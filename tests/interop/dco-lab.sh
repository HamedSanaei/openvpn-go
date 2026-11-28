#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

if [[ ${1:-} != --inside ]]; then
    if (( $# != 2 )); then
        echo 'Usage: dco-lab.sh pinned-openvpn-binary new-private-directory' >&2
        exit 2
    fi
    peer=$(realpath -- "$1")
    out=$(realpath -m -- "$2")
    test -x "$peer"
    mkdir -- "$out"
    trap 'sudo -n chown --no-dereference "$(id -u):$(id -g)" -- "$out"/*' EXIT
    sudo -n env "OPENVPN_DCO_SECONDS=${OPENVPN_DCO_SECONDS:-30}" \
        unshare --net --pid --fork --kill-child --mount-proc \
        bash "$(realpath -- "$0")" --inside "$peer" "$out"
    exit
fi

peer=$2 out=$3
seconds=${OPENVPN_DCO_SECONDS:-30}
[[ "$seconds" =~ ^[0-9]{1,3}$ ]] && (( 10#$seconds >= 3 && 10#$seconds <= 300 )) || {
    echo 'OPENVPN_DCO_SECONDS must be between 3 and 300' >&2
    exit 2
}
cd "$out"
links=$(ip -o link show)
if [[ "$links" != *': lo:'* || "$links" == *$'\n'* ]]; then
    echo 'DCO workload requires a disposable network namespace' >&2
    exit 2
fi
{
    "$peer" --version
    sha256sum "$peer"
    iperf3 --version
    uname -rm
    lscpu
    genl ctrl list
} > environment.txt
ip link set lo up

unshare --net sh -c 'echo "$$" >client.pid; exec sleep infinity' &
namespace=$!
for _ in {1..100}; do
    [[ -s client.pid ]] && break
    sleep 0.05
done
[[ $(cat client.pid) == "$namespace" ]]
client_ns() { nsenter --target "$namespace" --net "$@"; }
client_ns ip link set lo up
ip link add lab-server type veth peer name lab-client
ip link set lab-client netns "$namespace"
ip addr add 198.18.0.1/30 dev lab-server
ip link set lab-server up
client_ns ip addr add 198.18.0.2/30 dev lab-client
client_ns ip link set lab-client up

mkdir pki
trap 'rm -f -- pki/ca.key pki/server.key pki/client.key' EXIT
(
    cd pki
    openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -noenc -days 1 -subj /CN=dco-lab-ca -keyout ca.key -out ca.pem
    for role in server client; do
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -noenc -subj "/CN=dco-lab-$role" -keyout "$role.key" -out "$role.csr"
        printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=%sAuth\n' "$role" > "$role.ext"
        openssl x509 -req -days 1 -in "$role.csr" -CA ca.pem -CAkey ca.key \
            -CAcreateserial -extfile "$role.ext" -out "$role.pem"
    done
) > pki-generation.log 2>&1

device=tun-dcolab
common=(--dev "$device" --dev-type tun --proto udp4 --ca "$out/pki/ca.pem"
        --data-ciphers AES-256-GCM --tls-version-min 1.2 --verb 3 --reneg-sec 15)
server=(--local 198.18.0.1 --port 43119 --server 10.82.0.0 255.255.255.0
        --topology subnet --dh none --keepalive 1 5
        --cert "$out/pki/server.pem" --key "$out/pki/server.key" --remote-cert-tls client)
client=(--client --remote 198.18.0.1 43119 --nobind
        --cert "$out/pki/client.pem" --key "$out/pki/client.key" --remote-cert-tls server
        --verify-x509-name dco-lab-server name)

measure() {
    local backend=$1 mss=$2 repeat=$3
    local prefix="$backend-$mss-$repeat" expected=ovpn
    local server_pid client_pid echo_pid ping_pid
    local -a flags=()
    if [[ "$backend" == userspace ]]; then
        flags=(--disable-dco)
        expected=tun
    fi
    "$peer" "${common[@]}" "${server[@]}" "${flags[@]}" > "$prefix.server.log" 2>&1 &
    server_pid=$!
    nsenter --target "$namespace" --net "$peer" "${common[@]}" "${client[@]}" "${flags[@]}" > "$prefix.client.log" 2>&1 &
    client_pid=$!
    for _ in {1..160}; do
        if grep -q 'Initialization Sequence Completed' "$prefix.client.log" &&
            client_ns ping -c 1 -W 0.2 10.82.0.1 > /dev/null 2>&1; then
            break
        fi
        kill -0 "$server_pid" "$client_pid"
        sleep 0.1
    done
    grep -q 'Initialization Sequence Completed' "$prefix.client.log"
    ip -details -json link show dev "$device" > "$prefix.server-link.json"
    client_ns ip -details -json link show dev "$device" > "$prefix.client-link.json"
    python3 - "$expected" "$prefix.server-link.json" "$prefix.client-link.json" <<'PY'
import json
import sys

for path in sys.argv[2:]:
    with open(path) as stream:
        kind = json.load(stream)[0]["linkinfo"]["info_kind"]
    if kind != sys.argv[1]:
        raise SystemExit(f"{path}: expected {sys.argv[1]}, got {kind}")
PY
    iperf3 -s -1 -B 10.82.0.1 > "$prefix.iperf-server.log" 2>&1 &
    echo_pid=$!
    for _ in {1..100}; do
        [[ $(ss -H -ltn 'sport = :5201') ]] && break
        kill -0 "$echo_pid"
        sleep 0.05
    done
    grep '^cpu ' /proc/stat > "$prefix.cpu-before"
    client_ns ping -i 0.1 -w "$seconds" 10.82.0.1 > "$prefix.ping" &
    ping_pid=$!
    client_ns iperf3 -c 10.82.0.1 --bidir -P 2 -t "$seconds" -M "$mss" -J > "$prefix.iperf.json"
    grep '^cpu ' /proc/stat > "$prefix.cpu-after"
    wait "$echo_pid"
    wait "$ping_pid"
    if (( seconds >= 20 )) && (( $(grep -c 'Control Channel: TLS' "$prefix.client.log") < 2 )); then
        echo 'VPN peer did not finish a rekey during the measurement' >&2
        exit 1
    fi
    kill -TERM "$client_pid" "$server_pid"
    wait "$client_pid"
    wait "$server_pid"
    if ip link show dev "$device" > /dev/null 2>&1 ||
        client_ns ip link show dev "$device" > /dev/null 2>&1; then
        echo 'VPN link survived peer teardown' >&2
        exit 1
    fi
    printf '%s %s %s passed\n' "$backend" "$mss" "$repeat"
}

for mss in 256 1200; do
    measure userspace "$mss" 1
    measure dco "$mss" 1
    measure dco "$mss" 2
    measure userspace "$mss" 2
done
