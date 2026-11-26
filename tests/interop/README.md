# OpenVPN interoperability tests

The suites test TLS control, data traffic, rekey and generated client
profiles against disposable OpenVPN Community 2.6.22, 2.6.23 and 2.7.9 servers.

## Rules

- Never use a production VPN profile or credentials.
- Generate CA/server/client certificates and test credentials specifically for this suite.
- Pin server image versions; do not silently follow latest.
- Record OS, architecture, transport, TLS version, authentication mode and negotiated data cipher.
- Test UDP and TCP independently.
- Test certificate-only and username/password authentication.
- Test tls-auth, tls-crypt and tls-crypt-v2 independently.
- Test remote failover, mixed per-remote protocol settings, server restart, packet loss and rekey.
- Redact logs and remove generated private material after each run.

## Run the interoperability suite

Use a Linux test host with a TUN device and a pinned OpenVPN Community test binary
built against OpenSSL. Install the OpenSSL CLI for the independent TLS
exporter comparison. The tests generate disposable certificates, keys and
credentials in a temporary directory. The peer binds to loopback. The data
suite configures a test address on a disposable server TUN interface. Run
it in a disposable network namespace with permission to configure TUN, or
use an isolated VM.

From the repository root, with the pinned Go version on PATH:

```sh
export OPENVPN_INTEROP_BIN=/absolute/path/to/openvpn-2.6.23
export OPENVPN_INTEROP_VERSION=2.6.23
go mod download
sudo OPENVPN_INTEROP_BIN="$OPENVPN_INTEROP_BIN" OPENVPN_INTEROP_VERSION="$OPENVPN_INTEROP_VERSION" \
  GOMODCACHE="$(go env GOMODCACHE)" PATH="$PATH" \
  unshare --net sh -c 'ip link set lo up && go test -v -count=1 ./tests/interop'
```

Build a peer with `bash tests/interop/build-peer.sh VERSION BUILD_DIRECTORY`.
The script verifies the release archive's SHA-256 and detached signature.
Use `OPENVPN_INTEROP_VERSION=2.7.9` and its matching executable to include
the epoch negotiation policy cases.

The build and observed results are in the
[compatibility matrix](../../docs/COMPATIBILITY_MATRIX.md#evidence-records).
The ordinary unit suite runs without a server.

## Compare OpenVPN 3 Core with OpenVPN Go

On Ubuntu 24.04 with Go on PATH, install these test-only build dependencies.

~~~sh
sudo apt-get install --no-install-recommends build-essential cmake ninja-build pkg-config \
  iproute2 libasio-dev libcap-dev libcap-ng-dev libfmt-dev liblz4-dev liblzo2-dev \
  libjsoncpp-dev libssl-dev libxxhash-dev python3
~~~

Build the external Core CLI from the pinned release archive and run it
against the same Community server as OpenVPN Go. Build directories belong
outside the Go module. Use an isolated Linux host with `/dev/net/tun` and
permission to create network and mount namespaces.

~~~sh
lab="$(mktemp -d)"
server="$(bash tests/interop/build-peer.sh 2.6.23 "$lab/server")"
core="$(bash tests/interop/build-openvpn3.sh "$lab/core")"
core_sha="$(cut -d ' ' -f1 "$lab/core/ovpncli.sha256")"
go mod download
sudo env PATH="$PATH" GOTOOLCHAIN=local GOMODCACHE="$(go env GOMODCACHE)" GOPROXY=off \
  OPENVPN_INTEROP_BIN="$server" OPENVPN3_INTEROP_BIN="$core" \
  OPENVPN3_INTEROP_SHA256="$core_sha" OPENVPN3_COMPARISON_JSON="$lab/comparison.json" \
  unshare --net --mount bash -c 'ip link set lo up && exec go test -race -count=1 -v -run "^TestOpenVPN3Differential$" ./tests/interop'
~~~

The job reports results and the two executable hashes as
`openvpn3-conformance`. Exit status is nonzero on an unexpected outcome
or a failed expected match. TLS versions, negotiated ciphers and transport
come from the respective client observations. Traffic is verified using
a real UDP round trip through the server's TUN. The Go side uses the
public packet API. Core uses a kernel TUN in a second network namespace.
The harness generates its own profiles, PKI and credentials.
For local runs, read the root-owned report with `sudo cat "$lab/comparison.json"`.
[Results and reference pins](../../docs/COMPATIBILITY_MATRIX.md#openvpn-3-core-differential-reference)

`bash tests/interop/build-peer.sh 2.6.22 /path/to/disposable/build`
builds the second pinned version and prints its executable path.

Run `go test -v -count=1 -run '^TestProfilesOpenVPN26$' ./tests/interop`
in the same environment for the profile cases alone. They generate inline
UDP and externally referenced TCP profiles and use an authentication
marker to verify that certificate rejection precedes password submission.

Run `go test -v -count=1 -run '^TestFailover' ./tests/interop` for mixed
UDP/TCP fallback, server restart, SNI and terminal-error coverage. The
test keeps one forwarding tunnel through three authenticated sessions and
verifies bidirectional traffic after each switch.

For the Xray adapter test, build the pinned peer with
`bash tests/interop/build-xray-peer.sh /path/to/disposable/build` and
pass its executable path in `XRAY_INTEROP_BIN`. Inside the same
isolated Linux environment, run
`go test -race -v -run '^TestXrayEgressOpenVPN26$' ./tests/interop`.
The test provisions a temporary veth pair and a nested network
namespace. It needs Linux TUN and network and mount namespace permissions.
Use `unshare --net --mount` when running it.

## Historical AEAD policy

Run the separately pinned 2.4.12 and 2.5.11 probes on a disposable Linux
test host. Install the normal peer build tools and `iproute2`. The 2.4.12
builder compiles a private OpenSSL 1.1.1w for that executable.

~~~sh
version=2.4.12  # repeat with 2.5.11
lab="$(mktemp -d)"
peer="$(bash tests/interop/build-peer.sh "$version" "$lab")"
go mod download
sudo env PATH="$PATH" GOTOOLCHAIN=local GOMODCACHE="$(go env GOMODCACHE)" GOPROXY=off \
  OPENVPN_LEGACY_BIN="$peer" OPENVPN_LEGACY_VERSION="$version" \
  unshare --net sh -c 'ip link set lo up && exec go test -race -v -count=1 -run "^TestLegacyCommunityAEADPolicy$" ./tests/interop'
~~~

The legacy test expects verified TLS 1.2, then rejects the unsupported
data-channel negotiation before publishing a session.

The matrix also records [candidate coverage for older servers and MikroTik](../../docs/COMPATIBILITY_MATRIX.md#candidate-coverage-for-older-servers-and-mikrotik).
Test each legacy or RouterOS build in an isolated environment. For RouterOS,
record the exact build, platform and exported profile fixture. Capture whether
the connection used a fixed cipher and which data format and key derivation
were observed. Include a default-policy rejection test for each option that
requires explicit compatibility mode.

## Authorized external profiles

Use the opt-in test for a pinned lab router or an account authorized for
provider compatibility testing. It reports stable failure codes and
negotiation features, and can send a synthetic reply probe through the tunnel
before and after a reconnect. [Commands and observed results](../../docs/EXTERNAL_INTEROP.md)
