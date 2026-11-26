#!/usr/bin/env bash
set -euo pipefail
umask 077

# Run from the checkout root against the dedicated routeros-lab.sh namespace.
if [ "$#" -ne 2 ]; then
    echo "Usage from checkout root: routeros-matrix.sh private-directory signed-community-binary" >&2
    exit 2
fi
repo=$(pwd -P)
lab=$(realpath -- "$1")
peer=$(realpath -- "$2")
namespace=$(cat "$lab/namespace")
[[ "$namespace" =~ ^chr16-[0-9a-f]{8}$ ]] || exit 2
exec 9>"$lab/matrix.lock"
flock -n 9
test -f "$lab/1194-fixed.ovpn"
"$peer" --version | grep '^OpenVPN 2.6.23 '
go test -race -c -o "$lab/interop.test" ./tests/interop
sudo env OPENVPN_INTEROP_BIN="$peer" unshare --net sh -c '
    ip link set lo up
    exec "$1" -test.count=1 -test.run "^TestExternalProfileHarness$"
' sh "$lab/interop.test"

cd "$lab"
printf '%s\n' '/ppp/active/remove [find where name="chr-lab-user"]' > clear.rsc
clear_peer() {
    python3 "$repo/tests/interop/routeros-console.py" "$lab" "$lab/clear.rsc" >/dev/null
}

reference() {
    local port=$1 cipher=$2 label=$3
    clear_peer
    sudo ip netns exec "$namespace" bash -s -- "$peer" "$lab" "$port" "$cipher" "$label" <<'REF'
set -eu
umask 077
peer=$1 lab=$2 port=$3 cipher=$4 label=$5
"$peer" --config "$lab/$port.ovpn" --auth-user-pass "$lab/auth" --dev tun16ref \
    --data-ciphers "$cipher" --data-ciphers-fallback "$cipher" --auth none \
    --connect-retry-max 1 --verb 4 > "$lab/$label.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :' EXIT
for _ in $(seq 1 70); do
    if grep -q 'Initialization Sequence Completed' "$lab/$label.log"; then break; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep .2
done
grep -q 'Initialization Sequence Completed' "$lab/$label.log" || { echo "$label: reference initialization failed" >&2; exit 1; }
grep -q 'TLSv1.2' "$lab/$label.log" || { echo "$label: reference TLS version mismatch" >&2; exit 1; }
ping -q -I tun16ref -c 4 -i .3 -W 1 10.61.0.1 >/dev/null || {
    echo "$label: reference did not return ICMP within the echo window" >&2
    exit 1
}
python3 - "$lab/$label.log" "$label" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(errors="replace")
push = next((line for line in text.splitlines() if "Received control message: 'PUSH_REPLY" in line), "")
if ",peer-id " not in push or ",cipher " in push or "tls-ekm" in push:
    raise SystemExit("unexpected reference negotiation")
print(sys.argv[2], "reference verified TLS1.2 peer-id and echo")
PY
REF
}

probe() {
    local label=$1 profile=$2 credentials=$3 wanted=$4 rekey=$5 cipher=${6:-} phase=${7:-}
    clear_peer
    sudo ip netns exec "$namespace" env OVPN_EXTERNAL_PROFILE="$profile" \
        OVPN_EXTERNAL_ROOT="$lab" OVPN_EXTERNAL_AUTH_FILE="$credentials" OVPN_EXTERNAL_ECHO=10.61.0.1 \
        OVPN_EXTERNAL_EXPECT="$wanted" OVPN_EXTERNAL_REKEY="$rekey" \
        "$lab/interop.test" -test.v -test.count=1 -test.timeout=1m -test.run '^TestExternalProfile$' \
        > "$lab/$label.log" 2>&1 || { echo "$label: probe outcome did not match $wanted" >&2; return 1; }
    python3 - "$lab/$label.log" "$label" "$wanted" "$cipher" "$phase" <<'PY'
import json
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text()
for line in text.splitlines():
    at = line.find('{"profile"')
    if at >= 0:
        report = json.loads(line[at:])
        break
else:
    raise SystemExit("missing redacted report")
positive = sys.argv[3] in ("verified", "rekey_verified")
if positive:
    assert report["tls"] == "TLS 1.2"
    assert report["client_certificate"] and report["password_auth"]
    assert report["aead"] == sys.argv[4]
    assert report["derivation"] == "classic_km2"
    assert report["data_format"] == "data_v2"
    assert report["synthetic_round_trips"] == 2
    generations = report["generations"]
    assert len(report["attempts"]) == len(generations) == (1 if sys.argv[3] == "rekey_verified" else 2)
    for generation in generations:
        assert generation["packets_sent"] > 0 and generation["packets_received"] > 0
    if sys.argv[3] == "rekey_verified":
        assert report["verified_rekeys"] == 1
else:
    assert report["synthetic_round_trips"] == 0 and not report.get("generations")
    assert len(report["attempts"]) == 1 and report["attempts"][0]["phase"] == sys.argv[5]
    if sys.argv[2] == "default-policy":
        assert report["attempts"][0]["phase_steps"] == 1
print(sys.argv[2], "positive" if positive else "negative", report["stage"], report.get("code", ""),
      sys.argv[5], report.get("tls", ""), report.get("aead", ""), report.get("derivation", ""),
      report.get("data_format", ""), report["synthetic_round_trips"])
PY
}

for spec in '1194 AES-256-GCM' '1195 AES-256-GCM' '1196 AES-128-GCM' '1197 AES-128-GCM'; do
    read -r port cipher <<< "$spec"
    reference "$port" "$cipher" "$port-before-1"
    reference "$port" "$cipher" "$port-before-2"
    probe "$port-go-reconnect" "$lab/$port-fixed.ovpn" "$lab/auth" verified 0 "$cipher"
    probe "$port-go-rekey" "$lab/$port-fixed.ovpn" "$lab/auth" rekey_verified 1 "$cipher"
    reference "$port" "$cipher" "$port-after-1"
    reference "$port" "$cipher" "$port-after-2"
done

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 -subj /CN=Untrusted-CHR-Test-CA \
    -keyout negative-ca.key -out negative-ca.pem > negative-ca.log 2>&1
python3 - <<'PY'
import pathlib
import re

source = pathlib.Path("1194-fixed.ovpn").read_text()
wrong_ca = pathlib.Path("negative-ca.pem").read_text()
for name, text in {
    "name": source.replace("vpn.lab.test name", "wrong.lab.test name"),
    "ca": re.sub(r"(?s)<ca>.*?</ca>", "<ca>\n" + wrong_ca + "</ca>", source),
    "pin": source + "peer-fingerprint " + ":".join(["00"] * 32) + "\n",
    "cipher": source.replace("compat-fixed-aead AES-256-GCM", "compat-fixed-aead AES-128-GCM"),
}.items():
    pathlib.Path("negative-" + name + ".ovpn").write_text(text)
PY
printf 'chr-lab-user\ninvalid-disposable-password\n' > negative-auth
for case_name in ca name pin; do
    probe "negative-$case_name" "$lab/negative-$case_name.ovpn" "$lab/auth" connect:certificate_verification_failure 0 '' tls_verification
done
probe negative-cipher "$lab/negative-cipher.ovpn" "$lab/auth" connect:network_failure 0 '' key_method_read
probe negative-auth "$lab/1194-fixed.ovpn" "$lab/negative-auth" connect:authentication_failure 0 '' authenticated_push
probe default-policy "$lab/1194.ovpn" "$lab/auth" connect:operation_timed_out 0 '' key_method_fields
clear_peer
