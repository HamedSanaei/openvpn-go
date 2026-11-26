# Compatibility matrix

The initial reference peer is OpenVPN Community **2.6.23**, tag `v2.6.23` at
commit `49620843c487a7fee58e3030b7c88681c115e24e`. Use the official release
source with its detached signature for the disposable Linux server. Build
with OpenSSL and run with DCO disabled to exercise the user-space protocol.
The M2 control and M3 data scenarios passed with this reference server. [Official release](https://github.com/OpenVPN/openvpn/releases/tag/v2.6.23) · [Release archives](https://build.openvpn.net/downloads/releases/) · [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/)

| Scenarios | Control protection | Transport | Client authentication | First positive evidence |
|---|---|---|---|---|
| OV26-TLS | TLS with plain outer control packets | UDP, TCP | Certificate only, certificate plus password | M2 handshake, M3 data |
| OV26-TA | `tls-auth`, with matched `auth` digest and key directions | UDP, TCP | Certificate only, certificate plus password | M2 handshake, M3 data |
| OV26-TC | `tls-crypt` | UDP, TCP | Certificate only, certificate plus password | M2 handshake, M3 data |
| OV26-V2 | `tls-crypt-v2` against a server allowing non-cookie peers | UDP, TCP | Certificate only, certificate plus password | M2 handshake, M3 data |
| OV26-V2C | `tls-crypt-v2` with server `force-cookie` | UDP, TCP | Certificate only, certificate plus password | M2 handshake, M3 data |

Each row was exercised with each transport and authentication mode, TLS 1.2
and 1.3, and each forced data cipher. The resulting 120 positive cases cover
`P_DATA_V2`, IPv4 tunnel traffic and key method 2 with TLS exporter derivation.
The ciphers were `AES-256-GCM`, `AES-128-GCM` and `CHACHA20-POLY1305`.
Session, failover, IPv6 and negative cases have separate acceptance criteria.
[Protocol baseline](PROTOCOL_BASELINE.md) · [Test strategy](TEST_STRATEGY.md)

Use generated server and client certificates, a test-only CA and a server
name with a matching DNS SAN. For `tls-auth`, run the matrix with SHA-256 and
client direction `1`/server direction `0`. Exercise the additional approved
digests and symmetric key-direction mode with focused cases. For the two
`tls-crypt-v2` rows verify the cookie path with `force-cookie` and cover the
non-cookie path with an independent wire fixture if the 2.6.23 server still
chooses a cookie under `allow-noncookie`.

The 2.6.23 baseline excludes MFA/SSO and deferred interactive auth,
static-key mode, key method 1, legacy PRF fallback, compression, legacy data
ciphers, TAP, DCO, address floating, dynamic control wrapping, epoch data
formats, and Access Server or other OpenVPN releases without recorded results.
IPv6 transport and IPv6 tunnel traffic are focused tests, independent of the
IPv4 matrix. [Project scope](REQUIREMENTS.md)

Focused TCP tests cover password-only authentication, server-side optional
client certificates with and without a client identity, and required
client certificates. Failure cases cover a wrong password and invalid
server identity. Password-only operation requires an explicit client
policy. The DNS integration suite exercises authenticated resolver
changes and rejects stale and pending configurations during reconnect.
[Password-authentication tests](../tests/interop/password_test.go) · [DNS reconnect test](../tests/interop/dns_test.go)

## OpenVPN 3 Core differential reference

The differential harness uses the upstream OpenVPN 3 Core `ovpncli` from
release `3.11.8`, commit `4f3bdef73245d4ee9e8216c5d65baccc9568f6ef`.
Each run builds the external CLI from the SHA-256-pinned release source and
verifies the resulting binary against its recorded digest before use.
The harness also records the Community 2.6.23 server executable digest.
Core and OpenVPN Go use the same generated profile for each case.
[Core release](https://github.com/OpenVPN/openvpn3/tree/release/3.11.8) · [Test instructions](../tests/interop/README.md#compare-openvpn-3-core-with-openvpn-go)

| Observed case | Result |
|---|---|
| UDP, TLS 1.2 and AES-128-GCM | Matching negotiation and bidirectional UDP payload |
| TCP, TLS 1.3, AES-256-GCM, tls-auth and valid password | Matching negotiation and bidirectional UDP payload |
| UDP, TLS 1.3, ChaCha20-Poly1305 and tls-crypt | Matching negotiation and bidirectional UDP payload |
| UDP, TLS 1.3, AES-256-GCM and tls-crypt-v2 with forced cookie | Matching negotiation and bidirectional UDP payload |
| Wrong certificate name, wrong CA and wrong password | Both reject each profile with the corresponding failure category |
| Profile `connect-retry-max` | Core connects and passes traffic. The Go profile parser rejects the directive and exposes the retry limit through the caller's `RetryPolicy`. |

The report establishes the results for these generated cases. Add a case
for each new behavior before expanding compatibility claims.
[Differential tests](../tests/interop/openvpn3_test.go) · [Hardening workflow](../.github/workflows/hardening.yml)

## Candidate coverage for older servers and MikroTik

The historical Community rows record isolated AEAD negotiation probes. The RouterOS row records an isolated CHR evaluation, with hardware validation pending. The 2.6.23 baseline
remains the release reference. Exercise older server builds only in isolated
test environments. OpenVPN Community has ended upstream support for 2.4 and
2.5. [OpenVPN release support](https://community.openvpn.net/Pages/Supported%20versions)

| Peer | Profile | Observation or open question |
|---|---|---|
| OpenVPN Community 2.5.11, commit `6fb2a2560845e15da8918c114fe020b4a06b3cef` | Verified TLS 1.2 over TCP, TUN, AES-256-GCM and AES-128-GCM configured, OpenSSL 3.0.13 | The server pushed `peer-id` and `cipher AES-256-GCM` and omitted `tls-ekm`. The Go client returned a protocol error before activating the session. |
| OpenVPN Community 2.4.12, commit `058407a89cb812115b383570b12f4c2fde500d39` | Verified TLS 1.2 over TCP, TUN, AES-256-GCM and AES-128-GCM configured, private OpenSSL 1.1.1w | The server pushed `peer-id` and omitted both the negotiated cipher and `tls-ekm`. The Go client returned a protocol error before activating the session. |
| MikroTik CHR 7.25.2 x86_64 | TLS 1.2, certificate and PPP password, TCP/UDP, fixed AES-256-GCM and AES-128-GCM | The Community reference verified identity, packet traffic and reconnect. Go timed out during initial setup in all four cases; the repeat returned UDP timeouts and TCP network failures. The reference push included a peer ID and omitted cipher and exporter negotiation. Hardware target `RB5009UG+S+IN`, arm64, 7.25.2, is pending. [Lab results](EXTERNAL_INTEROP.md#mikrotik-routeros) |

[OpenVPN 2.5.11](https://github.com/OpenVPN/openvpn/releases/tag/v2.5.11) · [OpenVPN 2.4.12](https://github.com/OpenVPN/openvpn/releases/tag/v2.4.12) · [OpenVPN 2.5 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-5-manual/) · [OpenVPN 2.6 changes](https://github.com/OpenVPN/openvpn/blob/v2.6.23/Changes.rst#overview-of-changes-in-26) · [MikroTik OpenVPN documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/2031655/OpenVPN)

Both historical probes used generated certificates on an isolated Linux
amd64 host with compression and plugins omitted from the reference build.
The test captures the authenticated push and checks the rejection before
the client publishes control information or an active endpoint.
[Legacy probe](../tests/interop/version_policy_test.go) · [Signed reference builds](../tests/interop/build-peer.sh)

Any future legacy policy must be an explicit, per-endpoint opt-in for
`AES-256-GCM` or `AES-128-GCM`, verified server identity and TLS 1.2 or
later. Confine legacy derivation to that mode. Require an independently
verified key method 2 transcript and vectors before adding it. Require
explicit AEAD selection and a reviewed 2.4 NCP policy before advertising
`IV_NCP=2`. Review any `DATA_V1` framing separately. Compression, CBC
and older TLS stay outside this policy. Verify packet exchange and rekey
for every permitted combination before enabling the mode.

Review protocol differences in M2 and M3 before adding any compatibility
mode. A mode that permits the older data key derivation, a fixed cipher,
or another data packet format must be explicitly selected for its endpoint.
A missing exporter or cipher signal on a default endpoint remains a
terminal negotiation error. All candidates require verified server
identity and TLS 1.2 or later. Choose separate compatibility cases for
RouterOS 6.x or existing CBC-only profiles if those are required. Such
cases need their own approved security policy and interoperability
evidence before implementation.

The M4 parser rejects an unapproved `cipher` and any `data-ciphers-fallback`
directive with a line-numbered diagnostic. A supported AEAD in `cipher`
produces an explicit warning because the client requires negotiated
AEAD, TLS exporter derivation and a peer ID. A RouterOS configuration
that requires a fixed cipher without negotiation falls outside that
policy. M6 evidence must show a verified handshake, bidirectional IP
traffic, and rekey or a controlled reconnect on the specified build. Verify
that a required-but-unconfigured mode, wrong server identity or mismatched
cipher fails. [Pinned CHR lab and hardware target](EXTERNAL_INTEROP.md#mikrotik-routeros)

The external profile record tracks Access Server exports and the pending
authorized provider cases. [Provider and Access Server results](EXTERNAL_INTEROP.md#provider-and-access-server-profiles)

## OpenVPN Community 2.7.9

The signed stable reference is tag `v2.7.9` at
`7b60c2aa34992639691e3a2d651fe27301e2e9d5`. The local Linux amd64
peer used OpenSSL 3.0.13 with DCO disabled. CI records the exact TLS
backend of each build and retains both 2.6 peers.
[Official 2.7.9 release](https://github.com/OpenVPN/openvpn/releases/tag/v2.7.9) · [Hardening workflow](../.github/workflows/hardening.yml)

| Scenario | Observed result |
|---|---|
| UDP and TCP, TLS 1.2 and 1.3, certificate and optional password, plain TLS, tls-auth, tls-crypt, or tls-crypt-v2 with and without cookies | All 120 IPv4 traffic cases negotiated exporter derivation and the expected AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305 cipher over classic `DATA_V2`. |
| IPv6 and classic rekey | IPv6 traffic passed over IPv6 UDP. Server-initiated rekey and client-initiated key-ID rollover retained packet traffic. |
| Control and failure cases | Wrong identity, CA and password, cipher mismatch and compression were rejected. Failover and reconnect cases passed. |
| Epoch | Two 2.7.9 reference processes selected `aead-epoch`. The project client passed classic sessions and rejected a forced authenticated epoch push. |

Epoch framing and DCO remain outside the supported profile.
[Epoch evaluation](EPOCH_DATA.md) · [Live tests](../tests/interop/data_test.go)

## Evidence records

M2 passed all 20 baseline control scenarios over TLS 1.2, with
`AES-256-GCM` selected. A focused TCP case passed over TLS 1.3. The suite
also passed UDP loss and reordering and rejection of wrong server names,
wrong CAs and wrong passwords. The test peer was built from the signed
2.6.23 release archive on Ubuntu 24.04 amd64 with OpenSSL 3.0.13 and DCO
disabled. It ran in a disposable loopback-only network namespace.
[Interop suite](../tests/interop/control_test.go) · [Test instructions](../tests/interop/README.md)

M3 passed a UDP payload exchange in both directions through the client
packet API and the server's Linux TUN interface in all 120 IPv4 matrix cases.
A focused case passed IPv6 tunnel traffic over IPv6 UDP. A UDP tls-crypt-v2
case exercised server-initiated rekey. A TCP tls-auth case exercised
eight client-initiated rekeys, including key ID 7 to 1, with a UDP payload
exchange through every generation. Both rekey cases used TLS 1.3,
`AES-256-GCM`, certificate-plus-password authentication and server-issued
authentication tokens. The same signed reference build was used.
[Data and rekey suite](../tests/interop/data_test.go)

The Go TLS exporter matched all 256 bytes from OpenSSL 3.0.13 in
verified TLS 1.2 and 1.3 sessions. [Exporter test](../tests/interop/exporter_test.go)

M4 passed ten generated profile cases with OpenVPN Community 2.6.23 on
Ubuntu 26.04 LTS amd64 using OpenSSL 3.5.5 and DCO disabled. The source
archive matched the SHA-256 recorded for M2. Each of the five control
scenarios negotiated `AES-256-GCM` with certificate-plus-password
authentication. UDP used inline material and TLS 1.2. TCP used external
material, connection blocks and TLS 1.3. The test server observed no
password submission after rejection of an exact name or a SAN under
name-prefix policy. An accepted prefix and SAN reached password
verification and a wrong password produced a redacted terminal error.
[Profile suite](../tests/interop/profile_test.go) · [Test instructions](../tests/interop/README.md)

M5 used the same OpenVPN 2.6.23 Linux amd64 build as M4. A silent
UDP endpoint timed out before the client connected to a TCP server.
The test stopped that server, verified traffic through a UDP fallback
with a different certificate identity, restarted the TCP server, and
verified traffic after switching back. Each session negotiated TLS 1.2 and
`AES-256-GCM`. The test captured the actual SNI in each ClientHello.
The initial link rekeyed with server-issued token support. The UDP
fallback accepted the original password through its independent verifier.
Wrong identity, CA and password checks stopped after one attempt.
[Failover and reconnect suite](../tests/interop/failover_test.go)

M6 reran the full suite for 2.6.23 and added 2.6.22
(`c9b790f5b9e8ebca5da38c22f479c31bb8d33686`) with the same isolated
Linux amd64 harness and OpenSSL 3.5.5. Both passed the 120 IPv4 traffic
cases and focused IPv6, rekey, profile, failover and negative cases.
The additional tests passed four HMAC digests on both transports,
including bidirectional and reversed key directions. Both builds also
rejected a compression push and cipher mismatch and honored `ping-exit`.
The M6 traffic matrix covers the listed 2.6 peers. [OpenVPN 2.6.22 release](https://github.com/OpenVPN/openvpn/releases/tag/v2.6.22) · [New cases](../tests/interop/hardening_test.go)

The Linux M7 adapter passed an IPv4 TCP/UDP echo through stock Xray
26.10.21 and the authenticated OpenVPN TCP tunnel before and after
restarting the peer. The test also checks canceled forwarding and
failure of an Xray outbound bound to a missing interface. The target
3x-ui checkout accepted the outbound JSON through its config validator.
[Pinned integration](adr/0007-xray-linux-egress.md) · [Live test](../tests/interop/xray_test.go)

Record the server release and commit, archive or image digest, OS and
architecture, TLS backend and build, scenario, transport, identity policy,
authentication, observed TLS version/cipher/data format, fixture revision and
result. Use an immutable image digest once the harness has built the server.
Only a passing record supports a compatibility claim. Reassess the server pin
before certifying a release. [Interop harness plan](../tests/interop/README.md)
