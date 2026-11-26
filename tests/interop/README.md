# OpenVPN interoperability tests

The suites test TLS control, data traffic and rekey against disposable OpenVPN Community 2.6.23 servers.

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

Use a Linux test host with a TUN device and a pinned OpenVPN 2.6.23 binary
built against OpenSSL. Install the OpenSSL CLI for the independent TLS
exporter comparison. The tests generate disposable certificates, keys and
credentials in a temporary directory. The peer binds to loopback. The data
suite configures a test address on a disposable server TUN interface. Run
it in a disposable network namespace with permission to configure TUN, or
use an isolated VM.

From the repository root, with the pinned Go version on PATH:

```sh
export OPENVPN_INTEROP_BIN=/absolute/path/to/openvpn-2.6.23
sudo OPENVPN_INTEROP_BIN="$OPENVPN_INTEROP_BIN" PATH="$PATH" \
  unshare --net sh -c 'ip link set lo up && go test -v -count=1 ./tests/interop'
```

The build and observed results are in the
[compatibility matrix](../../docs/COMPATIBILITY_MATRIX.md#evidence-records).
The ordinary unit suite runs without a server.

The matrix also records [candidate coverage for older servers and MikroTik](../../docs/COMPATIBILITY_MATRIX.md#candidate-coverage-for-older-servers-and-mikrotik).
Test each legacy or RouterOS build in an isolated environment. For RouterOS,
record the exact build, platform and exported profile fixture. Capture whether
the connection used a fixed cipher and which data format and key derivation
were observed. Include a default-policy rejection test for each option that
requires explicit compatibility mode.
