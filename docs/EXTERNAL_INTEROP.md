# External OpenVPN compatibility tests

Run these tests from a disposable lab using a router or account explicitly
authorized for testing. Keep downloaded profiles, credential files,
keys and peer logs in a private directory outside the checkout. Publish
only the probe's redacted JSON and a summary of the exact test case.

## Running the probe

The probe uses the regular profile parser and client. It records registered
directive names, warning and failure codes, validated transport and control
protection, authentication mode, and the negotiated TLS version and AEAD
cipher when a connection succeeds. It keeps profile values, endpoints,
assigned addresses and raw errors out of the report.

~~~sh
export OVPN_EXTERNAL_PROFILE=/path/to/private/client.ovpn
export OVPN_EXTERNAL_ROOT=/path/to/private
export OVPN_EXTERNAL_AUTH_FILE=/path/to/private/auth.txt
go test -v -count=1 -timeout 1m -run '^TestExternalProfile$' ./tests/interop
~~~

`OVPN_EXTERNAL_ROOT` authorizes profile-relative material references.
`OVPN_EXTERNAL_AUTH_FILE` supplies the two-line username and password for
a bare `auth-user-pass` directive. Omit whichever variables the profile
doesn't need. Set `OVPN_EXTERNAL_PASSWORD_ONLY=1` only for a test profile
designed to use verified TLS and password authentication without a client
certificate. The default client policy still requires verified server
identity, TLS 1.2 or later, negotiated AEAD, TLS exporter key derivation
and a peer ID.

The probe selects the first declared remote. Use `OVPN_EXTERNAL_REMOTE`
to select another using its one-based profile index. Repeat per transport
and profile. The default expected outcome is `connected`, which verifies
negotiation. To verify data and reconnect, set `OVPN_EXTERNAL_ECHO` to an
IPv4 ICMP echo endpoint owned by the test lab and set
`OVPN_EXTERNAL_EXPECT=verified`. The probe sends only a synthetic nonce
through the packet API, closes the first peer transport and checks another
round trip through the new session. It installs no host routes or DNS
settings. To reproduce a known rejection, set the expected outcome to its
reported `stage:code`, for example `parse:unsupported_directive`.
An unexpected outcome makes the test fail. `OVPN_EXTERNAL_REKEY=1` with
`OVPN_EXTERNAL_EXPECT=rekey_verified` keeps one connection and verifies a
second round trip after a key change in that connection. A redacted last
attempt phase and completed phase count distinguish setup failures that
share a public error code.

## MikroTik RouterOS

The virtual reference is **CHR 7.25.2 stable, x86_64** on QEMU 10.2.1
under Linux amd64 WSL2 (`6.18.33.2-microsoft-standard-WSL2`). A single
TAP link in a dedicated network namespace connects the host and the
snapshot guest. The namespace has no uplink or default route. The official ZIP
`chr-7.25.2.img.zip` had SHA-256
`b0df0acb3f2070fb94d9e30bd8a8566bb622034786bb4f759f837cf2aa05bacb`.
The physical target is **RB5009UG+S+IN, arm64, RouterOS 7.25.2**.
That target is pending a run on authorized hardware.
[MikroTik stable releases](https://download.mikrotik.com/routeros/latest-stable.rss) ·
[Pinned CHR archive](https://download.mikrotik.com/routeros/7.25.2/chr-7.25.2.img.zip) ·
[RB5009 board](https://mikrotik.com/product/rb5009ug_s_in)

Run from the checkout root on Linux with TUN/TAP, QEMU, OpenSSL, Python 3,
iproute2, curl, unzip, sudo and the Go toolchain declared in `go.mod`.
Use private directories outside the checkout. The lab creates disposable
PKI and PPP credentials, then configures each IP-mode listener to require
the client certificate, PPP credentials and TLS 1.2. The PPP address pool
allows separate leases. The matrix clears the disposable principal's
active sessions between probe processes, waits for the previous reference
process to exit, and tests the same listener twice before and twice after
each pair of Go probes.

~~~sh
scratch=$(mktemp -d)
peer=$(bash tests/interop/build-peer.sh 2.6.23 "$scratch/community")
bash tests/interop/routeros-lab.sh start "$scratch/chr"
bash tests/interop/routeros-matrix.sh "$scratch/chr" "$peer"
bash tests/interop/routeros-lab.sh stop "$scratch/chr"
~~~

The matrix first runs `TestExternalProfileHarness` against the signed
Community 2.6.23 build (`49620843c487a7fee58e3030b7c88681c115e24e`). The
generated profiles verify the server role and exact test hostname using
the lab CA. The Go profiles specify `compat-fixed-aead` for the selected
cipher. Community uses matching `--data-ciphers` and
`--data-ciphers-fallback`. The PPP interface serves the IPv4 echo target.
The probe prints only normalized results. Keep profiles, console output,
captures and raw peer logs under the private directories.
[RouterOS OpenVPN](https://help.mikrotik.com/docs/spaces/ROS/pages/2031655/OpenVPN) ·
[Server settings](https://manual.mikrotik.com/docs/cli-reference/interface/ovpn-server/server/)

| CHR profile | Community 2.6.23 before and after | Go fixed-AEAD policy |
|---|---|---|
| TCP 1194, AES-256-GCM | Verified TLS 1.2 identity and ICMP in four independent sessions | Verified TLS 1.2, `classic_km2`, `data_v2`, traffic after reconnect and rekey |
| UDP 1195, AES-256-GCM | Verified TLS 1.2 identity and ICMP in four independent sessions | Verified TLS 1.2, `classic_km2`, `data_v2`, traffic after reconnect and rekey |
| TCP 1196, AES-128-GCM | Verified TLS 1.2 identity and ICMP in four independent sessions | Verified TLS 1.2, `classic_km2`, `data_v2`, traffic after reconnect and rekey |
| UDP 1197, AES-128-GCM | Verified TLS 1.2 identity and ICMP in four independent sessions | Verified TLS 1.2, `classic_km2`, `data_v2`, traffic after reconnect and rekey |

Each Go row used a verified server identity, the listed cipher, and two
successful synthetic round trips across two connection generations. A
separate run completed two round trips in one generation, one before
key change and one after. Community received a peer ID and IPv4 assignment
in an authenticated push with neither `cipher` nor `tls-ekm`.

The earlier runs recorded timeouts on all four listeners, then UDP
timeouts and TCP network failures on a repeat. The rebuilt baseline
reproduced `connect:operation_timed_out` at `reset_ack` on all four.
A private packet capture showed CHR sending a server reset with no
acknowledgement, then acknowledging the client reset separately. The Go
client had required both in the reset packet. Handling the split proof
reached verified TLS and exposed a second difference. The authenticated
CHR key-method response carried the OCC options field without the modern
trailing fields. The fixed policy validates the cipher in this response.
CHR's authenticated push supplied `peer-id` without exporter selection.
The data-channel capture confirmed `P_DATA_V2` framing.
[Design and regression rationale](adr/0009-fixed-aead-compatibility.md)

The additional OpenVPN 3 Core 3.11.8 reference used the same four listener
profiles with the fixed cipher specified as `cipher`. Core connected with
TLS 1.2 and the expected AES-GCM cipher, and IPv4 ICMP echo bound to its
tunnel interface passed on all four listeners. The Core reference ran
one session per listener. [Core pin and build](../tests/interop/README.md#compare-openvpn-3-core-with-openvpn-go)

Wrong CA, hostname and pin returned `connect:certificate_verification_failure`
during `tls_verification`. CHR closed the mismatched fixed-cipher connection
during `key_method_read`, reported as `connect:network_failure`. A synthetic
test independently checks that the client rejects a contradictory cipher
in a complete authenticated reply. A wrong PPP password returned
`connect:authentication_failure` during `authenticated_push`. The TCP
AES-256-GCM default-policy probe still returned `connect:operation_timed_out`
during `key_method_fields`. All six checks reported zero traffic and no
verified generations.

On Linux with Go 1.26.11 and OpenSSL 3.5.5, race-enabled suites ran with
Community 2.6.22, 2.6.23 and 2.7.9, including the loss/rekey and
Xray 26.10.21 fixtures. Core 3.11.8 ran in the
Community differential harness. Signed Community 2.4.12 and 2.5.11
retained the default-policy rejection. The package, race, vet, module
verification and fuzz checks are separate from the CHR matrix. The
hosted jobs were run against implementation commit `ae771e2`.
[Interop commands](../tests/interop/README.md) · [CI logs](https://github.com/HamedSanaei/openvpn-go/actions/runs/45897905931) · [Hardening logs](https://github.com/HamedSanaei/openvpn-go/actions/runs/45897902334) · [Lossy soak logs](https://github.com/HamedSanaei/openvpn-go/actions/runs/45898243377)

Qualification is limited to these four virtual IPv4, IP-mode cases with
plain outer control and TLS 1.2. Physical RB5009 qualification awaits
authorized hardware. RouterOS 6.x, other hardware/releases, fixed-AEAD
IPv6 and protected control wrappers have no qualification here.
`DATA_V1`, CBC, compression, TAP and static-key mode are unsupported.
An independent security review of the compatibility path is pending.

## Provider and Access Server profiles

Run the probe against one unchanged export per authorized test case.
Record the export type, transport, authentication mode, control protection,
exact available server version and the stage/code. A server version can be
marked undisclosed when the provider does not expose it. List any tested
profile edits as separate cases.

A self-hosted Access Server lab used **3.2.4** (`3.2.4-f3c295a7-Ubuntu26`),
with the official Linux amd64 container pinned to
`docker.io/openvpn/openvpn-as@sha256:6b8252ead84638fb5d6bf1d617b07299d170c5102245675e3c1720bbeb9ac6e2`.
Two exports were generated using a disposable local account and kept outside
this repository. Both advertise TLS 1.3 and carry inline CA, certificate,
key and `tls-crypt-v2` material. The original exports request
`cipher AES-256-CBC`, which is outside this project's AEAD-only policy.

| Access Server export | Go probe outcome | Traffic / reconnect |
|---|---|---|
| Auto-login | `parse:unsupported_directive` (`cipher`, policy-disabled) | Not attempted |
| User-locked (`auth-user-pass`) | `parse:unsupported_directive` (`cipher`, policy-disabled) | Not attempted |

The external Community reference attempts also failed to reach the lab
listener (connection refused); no successful Access Server negotiation
or transport interoperability is established by this run. The reported
parser rejection is reproducible without network access. Reconfigure an
AEAD-only lab and repeat with a new, separately identified export before
claiming compatibility. No security policy was relaxed to accept these
profiles. [Access Server image](https://hub.docker.com/r/openvpn/openvpn-as)

| Provider | Export to test | Status |
|---|---|---|
| Proton VPN | Authorized manual exports with explicitly provisioned identity | Twelve original exports verified under the opt-in import. See the [redacted results](#proton-vpn). |
| Windscribe | Authorized manual OpenVPN configuration from the Config Generator | Pending authorized account and export |
| ExpressVPN | OpenVPN configuration and credentials from Manual Configuration | Pending authorized account and export |

[Proton VPN manual setup](https://protonvpn.com/support/vpn-login) ·
[Windscribe Config Generator](https://windscribe.com/getconfig/openvpn) ·
[ExpressVPN manual setup](https://www.expressvpn.com/support/vpn-setup/manual-config-for-windows-with-openvpn/)

### Proton VPN

The authorized lab covered twelve unchanged manual exports for one IPv4
server, six TCP and six UDP. The strict importer rejected all twelve
at `setenv`. The opt-in import accepted all twelve with the original
inline CA, tls-crypt and password authentication. The expected certificate
name was corroborated independently by querying Cloudflare and Google
HTTPS DNS resolvers for the provider-owned name and matching the A record
to the configured remote. The probe then required the exact name and
server certificate purpose alongside the exported CA. No endpoint names,
addresses, account material or profiles are published.

| Live case | Outcome |
|---|---|
| OpenVPN Community 2.6.23 reference, one export per transport | TLS 1.3, AES-256-GCM and authenticated session initialization. The reference disabled OS interface/route effects and omitted the known DNS hooks in its temporary input. |
| OpenVPN Go, six original TCP exports and all three distinct TCP candidates | All established TLS 1.3 and AES-256-GCM with a TLS exporter and `DATA_V2`. Each passed an IPv4 gateway echo before and after intentionally interrupting the transport. |
| OpenVPN Go, six original UDP exports and all five distinct UDP candidates | All established the same security parameters and passed the gateway echo and reconnect checks. |
| Authenticated transport hints | The server sent legacy exit notification and `TCP_NODELAY` hints, plus socket buffer counts over UDP. Go validates their syntax and keeps transport configuration caller-owned. |

The application traffic test attached a Linux TUN in a disposable network
namespace with no ordinary egress interface. A UDP DNS query to the
authenticated VPN resolver and an IPv4 HTTPS request through that TUN
passed on a representative TCP profile and a representative UDP profile.
The outer OpenVPN socket remained outside the namespace. The test
installed no host routes or host DNS configuration.

An optional two-second client rekey passed over UDP. Forced TCP rekey
lost the echo in one run and replaced the session in three serial runs.
The supplied exports specify `reneg-sec 0`. The normal importer preserves
that setting, and the probe overrides it only when explicitly asked to
test a forced rekey. This evidence does not certify forced TCP rekey
against the provider.

The provider's server build is undisclosed. These observations cover the
uploaded profiles, one authorized account and one IPv4 endpoint. The
import deliberately recognizes only the tested Linux DNS-hook group and
Windows DNS hint. It does not execute hooks or install a DNS leak policy.
[Import policy](PROFILE.md#proton-vpn-manual-exports) · [Proton OpenVPN configuration](https://protonvpn.com/support/vpn-config-download)

To reproduce the authenticated gateway and reconnect checks, select an
export and pass the independently verified name and credential file.

~~~sh
OVPN_EXTERNAL_PROFILE="$VPN_PROFILE" \
OVPN_EXTERNAL_PASSWORD_ONLY=1 \
OVPN_EXTERNAL_PROTON_SERVER_NAME="$VPN_SERVER_NAME" \
OVPN_EXTERNAL_AUTH_FILE="$VPN_AUTH_FILE" \
OVPN_EXTERNAL_ECHO=gateway OVPN_EXTERNAL_EXPECT=verified \
go test -race -v -count=1 -timeout 1m -run '^TestExternalProfile$' ./tests/interop
~~~

`OVPN_EXTERNAL_REMOTE` selects a one-based candidate. Use
`OVPN_EXTERNAL_REKEY=1` and `OVPN_EXTERNAL_EXPECT=rekey_verified` for the
separate forced-rekey probe. [Synthetic negative tests](../tests/interop/password_test.go)

#### Country and Secure Core exports

The later private batch contained 13 Country exports and 12 Secure Core
exports. The original files list multiple numeric IPv4 remotes and use a
20-second server poll timeout. The IP-SAN import verified the exact
address of each selected remote against its leaf certificate, using the
exported CA and server certificate purpose. The importer kept the remote
list and random selection policy.

| Export group | Verified profiles | Distinct address and transport pairs exercised |
|---|---:|---:|
| Country | 13 of 13 | 13 |
| Secure Core | 12 of 12 | 10 |

Every profile established TLS 1.3, AES-256-GCM, TLS exporter derivation and
`DATA_V2` with the authorized account. The live probe passed an IPv4 echo
with the tunnel gateway before and after reconnect. The certificate
preflight found a matching IP SAN for all nine distinct configured IPv4
addresses. The pair counts above include overlap between the groups.

A separate TUN lab verified a UDP DNS exchange with the negotiated
resolver and IPv4 HTTPS through a network namespace with no ordinary
egress interface. It passed for a representative TCP export and UDP
export in each group. The lab kept host routes and DNS settings outside
the test scope. The results cover sampled remote ports and the client-facing tunnel. The
provider's internal routing is outside the scope of the probe.

~~~sh
OVPN_EXTERNAL_PROFILE="$VPN_PROFILE" \
OVPN_EXTERNAL_PASSWORD_ONLY=1 \
OVPN_EXTERNAL_PROTON_VERIFY_IP=1 \
OVPN_EXTERNAL_AUTH_FILE="$VPN_AUTH_FILE" \
OVPN_EXTERNAL_ECHO=gateway OVPN_EXTERNAL_EXPECT=verified \
go test -race -v -count=1 -timeout 1m -run '^TestExternalProfile$' ./tests/interop
~~~

[Proton export types](https://protonvpn.com/support/vpn-config-download) ·
[Secure Core documentation](https://protonvpn.com/support/secure-core-vpn)
