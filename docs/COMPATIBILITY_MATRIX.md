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

The approved 2.6.23 scope excludes password-only servers, MFA/SSO and deferred interactive auth,
static-key mode, key method 1, legacy PRF fallback, compression, legacy data
ciphers, TAP, DCO, address floating, dynamic control wrapping, epoch data
formats, and Access Server or other OpenVPN releases without recorded results.
IPv6 transport and IPv6 tunnel traffic are focused tests, independent of the
IPv4 matrix. [Project scope](REQUIREMENTS.md)

## Candidate coverage for older servers and MikroTik

These candidates extend the compatibility investigation. The 2.6.23 baseline
remains the release reference. Exercise older server builds only in isolated
test environments. OpenVPN Community has ended upstream support for 2.4 and
2.5. [OpenVPN release support](https://community.openvpn.net/Pages/Supported%20versions)

| Candidate | First profiles to test | Protocol questions |
|---|---|---|
| OpenVPN Community 2.5.11, commit `6fb2a2560845e15da8918c114fe020b4a06b3cef` | TLS 1.2, TUN, UDP and TCP, AES-256-GCM and AES-128-GCM | Verify cipher negotiation and key method 2 with the OpenVPN PRF used before data-channel TLS exporter negotiation. |
| OpenVPN Community 2.4.12, commit `058407a89cb812115b383570b12f4c2fde500d39` | TLS 1.2, TUN, UDP and TCP, AES-256-GCM and AES-128-GCM | Verify the same key derivation and the 2.4 NCP behavior with `IV_NCP=2` only when both AES-GCM ciphers are offered. |
| MikroTik RouterOS 7.x as an OpenVPN server | IP mode, TLS 1.2, TCP and UDP where the chosen build offers them, explicit AES-256-GCM or AES-128-GCM, server CA validation, client certificate and PPP credentials | Pin the exact RouterOS build and capture its profile export. Determine the key derivation, peer ID and data packet format from observed negotiation. The vendor documents that cipher autonegotiation is unavailable and that the client profile must specify a cipher. |

[OpenVPN 2.5.11](https://github.com/OpenVPN/openvpn/releases/tag/v2.5.11) · [OpenVPN 2.4.12](https://github.com/OpenVPN/openvpn/releases/tag/v2.4.12) · [OpenVPN 2.5 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-5-manual/) · [OpenVPN 2.6 changes](https://github.com/OpenVPN/openvpn/blob/v2.6.23/Changes.rst#overview-of-changes-in-26) · [MikroTik OpenVPN documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/2031655/OpenVPN)

Review protocol differences in M2 and M3 before adding any compatibility
mode. A mode that permits the older data key derivation, a fixed cipher,
or another data packet format must be explicitly selected for its endpoint.
A missing exporter or cipher signal on a default endpoint remains a
terminal negotiation error. All candidates require verified server
identity and TLS 1.2 or later. Choose separate compatibility cases for
RouterOS 6.x or existing CBC-only profiles if those are required. Such
cases need their own approved security policy and interoperability
evidence before implementation.

M4 should import a generated RouterOS `.ovpn` fixture with the tested
server settings, or report exactly which directive or security policy
prevents use. M6 evidence must show a verified handshake, bidirectional IP
traffic, and rekey or a controlled reconnect on the specified build. Verify
that a required-but-unconfigured mode, wrong server identity or mismatched
cipher fails. Use a pinned Cloud Hosted Router image for reproducible
functional tests and add a run on the target hardware where its exact
build or behavior matters. [MikroTik CHR documentation](https://manual.mikrotik.com/docs/getting-started/installation-and-upgrade/install/chr-installation/)

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

Record the server release and commit, archive or image digest, OS and
architecture, TLS backend and build, scenario, transport, identity policy,
authentication, observed TLS version/cipher/data format, fixture revision and
result. Use an immutable image digest once the harness has built the server.
Only a passing record supports a compatibility claim. Reassess the server pin
before certifying a release. [Interop harness plan](../tests/interop/README.md)
