# Additional server interoperability

## SoftEther Developer Edition

Lab: Ubuntu 26.04, Linux 7.0.0-44, SoftEther Developer Edition 5.01 Build 9674 (Ubuntu package 5.01.9674+git20200806+8181039+dfsg3-1). The peer and client ran in a disposable Linux network namespace, with a local test user and SecureNAT virtual hub. No public listener was required.

The packaged server executable SHA-256 was `1e82b0aafdb32e8b14d88ad411488ca20c96c264fd34dd436ed0a1563d836b3d`. The OpenVPN Community 2.7.0 reference executable SHA-256 was `06d101129eec1816fe2f79910c292a33da2779e06e073dbc4de295ad6dc93ff6` (Ubuntu 2.7.0-1ubuntu1.4).

The stock L3 export contains AES-128-CBC, SHA1 and push-peer-info. Its L2 export requests TAP. Both remain rejected by strict import. An authorized administrator must explicitly provision an AEAD-capable Developer Edition endpoint, independently verify its CA and exact certificate common name, and supply an AEAD-only TUN profile. There is no automatic cipher or protocol fallback, and this is not raw export support.

### Opt-in policy

Example template (replace the placeholder with trusted provisioning data; supply credentials through profile.Options or the external harness, never commit them):

~~~ovpn
client
dev tun
remote vpn.example.test 1194 udp
nobind
remote-cert-tls server
verify-x509-name vpn.example.test name
tls-version-min 1.2
auth-user-pass
auth SHA256
data-ciphers AES-256-GCM
compat-fixed-aead-v1 AES-256-GCM
allow-compression no
reneg-sec 0
<ca>
... administrator-provisioned CA PEM ...
</ca>
~~~

Use `profile.Options.AllowPasswordOnly=true` only for this explicitly authorized password-only endpoint. With the direct client API set `Endpoint.FixedAEAD` and `Endpoint.FixedAEADDataV1=true`, require server usage, exact common name, explicit CA and credentials. System-root-only trust, TLS control protection modes, FIPS mode, DNS capability advertisement and interactive auth callbacks are not supported by this compatibility policy. The profile directive is not inferred from an error or an incomplete push.

Profile import reports a conflict at `compat-fixed-aead-v1` when the
caller configures passive `AUTH_PENDING`, a challenge callback or a web
authentication callback. Static credentials and a credential provider
remain available for this endpoint.

The import-policy regression was checked using the same packaged binary
in a fresh WSL2 namespace. All four fixed-GCM combinations passed
synthetic IPv4 traffic before and after reconnect. The server confinement
used a private mount for its state. [Developer Edition OpenVPN lab commands](https://github.com/SoftEtherVPN/SoftEtherVPN/blob/master/.ci/start-se-openvpn.sh)

The control-channel trace revealed a peer that retransmits its key-method response when sent five ACK IDs. Limit outbound ACK history to four only in this mode. The full four-field key-method response must contain the configured cipher in its options field. The authenticated push must not contain a peer ID or select TLS exporter derivation. Classic KM2 produces fresh per-generation keys; the AEAD DATA_V1 frame uses a one-byte opcode/key ID, four-byte packet ID authenticated as AAD, 16-byte tag, and ciphertext. Replay checks, key limits, old-generation overlap and conservative DATA_V2 MTU budgeting remain active. Unlike DATA_V2, DATA_V1 does not carry an authenticated peer ID; do not use this mode for modern peers.

### Observed results (2026-11-27)

| Transport | Cipher | TLS | Gateway echo before/after reconnect | Forced 5-second rekeys in same generation |
|---|---|---|---|---|
| UDP | AES-128-GCM | 1.2 | 2/2 | 2/2 |
| UDP | AES-256-GCM | 1.2 | 2/2 | 2/2 |
| TCP | AES-128-GCM | 1.2 | 2/2 | 2/2 |
| TCP | AES-256-GCM | 1.2 | 2/2 | 2/2 |

All four cases used local password authentication, plain TLS control, classic KM2 and DATA_V1. The rekey runs verified three gateway round trips each, with key IDs 0, 1 and 2 and no replacement connection. A premature UDP attempt before the listener was ready failed at reset_ack; the repeat after listener readiness passed both UDP cases. Wrong common name and wrong password on TCP were rejected with certificate and authentication failures respectively. The OpenVPN 2.7.0 reference initialized all four GCM combinations and a separate TCP AES-256-GCM trace verified 2/2 ICMP responses via a real TUN interface. The reference trace observed DATA_V1 frames. Neither raw exports nor credential files are included.

### Reproduce

Use a disposable SoftEther Developer Edition installation, a local test-only account, enabled OpenVPN L3 and SecureNAT, and wait until TCP/UDP listeners are ready. Export the public certificate from the authenticated management interface. Verify the identity out of band, then prepare the explicit profile above for each tested cipher and transport. Run the existing external harness in the same isolated lab:

~~~sh
OVPN_EXTERNAL_PROFILE="$VPN_PROFILE" \
OVPN_EXTERNAL_PASSWORD_ONLY=1 \
OVPN_EXTERNAL_AUTH_FILE="$VPN_AUTH_FILE" \
OVPN_EXTERNAL_ECHO=gateway OVPN_EXTERNAL_EXPECT=verified \
go test -race -v -count=1 -timeout 1m -run '^TestExternalProfile$' ./tests/interop
~~~

Repeat with `OVPN_EXTERNAL_REKEY=1 OVPN_EXTERNAL_REKEY_SECONDS=5 OVPN_EXTERNAL_REKEY_COUNT=2 OVPN_EXTERNAL_EXPECT=rekey_verified`. Use fresh generated credentials; never publish raw captures, private keys or real exports.

## Native Community 2.7.0

Same Linux host, disposable namespace, distro-packaged reference server: IPv6 data, rekey, DNS capabilities, native UDP frame budget and optional client identity suites passed. The reference harness accepts this exact additional version, still validating the binary's version output. This is targeted coverage, not a full certification of all patch releases.

## Remaining qualification

Access Server 3.2.4 is documented in ACCESS_SERVER.md. Its forced TCP rekey, live inner IPv6 and additional authentication/federation modes remain open. SoftEther Stable 4.44 Build 9807 and Pritunl 1.34.4822.59 are qualified within the scope below. Other SoftEther builds, certificate-only and interactive auth, L2 TAP, Go CBC support, and long-duration/load tests remain unqualified. Other management panels need separate export and configuration tests. RouterOS CHR 7.25.2 has its existing fixed DATA_V2 evidence, not hardware-wide certification. These are separate compatibility targets; unrelated VPN protocols are not supported by this package.


## SoftEther Stable 4.44 Build 9807 (2026-11-27)

The official [Stable release](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/tag/v4.44-9807-rtm) Linux x64 archive was downloaded over HTTPS and built with `make main`. Locally calculated SHA-256 (not an independently signed upstream checksum): archive `e423e7f94a9f1f97a77b6dd425ba54505f69978964ff97843c90cc619fb70599`, vpnserver `0b964f1609a4dd4e4c03dcb793c5e671f2c55ed2e6449b72f5bd30b506a0a370`. Built-in OpenSSL 3.0.9. Same isolated Ubuntu lab, local test account, L3 OpenVPN and SecureNAT.

| Transport | Cipher | Go TLS | Go reconnect echoes | Go same-generation rekeys |
|---|---|---|---|---|
| UDP | AES-128-GCM | 1.3 | 2/2 | 2/2 |
| UDP | AES-256-GCM | 1.3 | 2/2 | 2/2 |
| TCP | AES-128-GCM | 1.3 | 2/2 | 2/2 |
| TCP | AES-256-GCM | 1.3 | 2/2 | 2/2 |

All cases used the existing explicit DATA_V1 policy, classic KM2 and verified TLS; no protocol changes were necessary. Each 5-second rekey test verified three echoes with IDs 0, 1, 2 in one generation. The native Community 2.7.0 client independently passed TLS and ICMP with both transports and AES-128-CBC, AES-128-GCM and AES-256-GCM (6/6). CBC was exercised only by the reference client, not enabled in Go.

Stable exports a point-to-point configuration, unlike the tested Developer Edition subnet. Initial echo tests aimed at the wrong target; the corrected test used the SecureNAT private address and, for the reference TUN, an explicit host route to that address inside the namespace. Set OVPN_EXTERNAL_ECHO to that administrator-known private address rather than assuming the advertised point-to-point peer answers ICMP. In the lab this was 192.168.30.1. The original legacy CBC/TAP exports remain outside the strict import policy.

## Pritunl 1.34.4822.59 (2026-11-27)

Installed real Pritunl from its signed apt repository on Ubuntu 24.04 in an isolated chroot and network namespace on the Ubuntu 26.04 host. Versions: Pritunl 1.34.4822.59-0ubuntu1~noble, MongoDB 8.0.38, Community OpenVPN 2.7.9-noble1. The real management API created a test organization, attached user and TCP/UDP servers; exports were downloaded from the API without editing. A dummy uplink provided a default route without public network egress. The administrator obtained the expected exact CN from the public server certificate in the generated server configuration, independently of the VPN connection.

The old parser rejected the vendor export at ignore-unknown-option. The opt-in Pritunl importer retains CA, server usage, exact CN and client certificate verification. It permits only the specifically recognized compatibility hints, does not send UV_ID/UV_NAME, and removes the matching CBC fallback from the two known GCM/CBC offers. The 30-day export timer is shortened to the existing seven-day client ceiling, with a warning. No legacy data framing, arbitrary ignore rules, compression or CBC is enabled.

| Transport | Negotiated AEAD | Control | TLS / derivation / data | Reconnect echoes | Forced rekeys |
|---|---|---|---|---|---|
| UDP | AES-256-GCM | tls-auth | 1.3 / exporter / V2 | 2/2 | 2/2 |
| TCP | AES-256-GCM | tls-auth | 1.3 / exporter / V2 | 2/2 | 2/2 |
| UDP | AES-128-GCM | tls-auth | 1.3 / exporter / V2 | 2/2 | not run |
| UDP | CHACHA20-POLY1305 | tls-auth | 1.3 / exporter / V2 | 2/2 | not run |

Wrong CN was rejected in both AES-256-GCM cases; each rekey run verified three echoes in the same generation. All tests used actual certificate-only profiles. Do not infer PIN, OTP, SSO, site-to-site, high availability, DCO or performance qualification from these results.

### Reproduce

Use [Pritunl installation documentation](https://docs.pritunl.com/docs/installation) and a disposable Ubuntu 24.04 environment. For the versions above, start the dedicated MongoDB instance and Pritunl, provision a local organization and user, attach it to both test servers, choose the cipher, disable OTP/SSO for this certificate-only test, and wait for DH generation and listener readiness. Obtain each exact CN from the trusted public server certificate using the administrator's server configuration. Download each original profile from the management interface. Run:

~~~sh
OVPN_EXTERNAL_PROFILE="$VPN_PROFILE" \
OVPN_EXTERNAL_PRITUNL_SERVER_NAME="$VERIFIED_CN" \
OVPN_EXTERNAL_ECHO=gateway OVPN_EXTERNAL_EXPECT=verified \
go test -race -v -count=1 -timeout 1m -run '^TestExternalProfile$' ./tests/interop
~~~

Repeat with OVPN_EXTERNAL_REKEY=1, OVPN_EXTERNAL_REKEY_SECONDS=5, OVPN_EXTERNAL_REKEY_COUNT=2 and OVPN_EXTERNAL_EXPECT=rekey_verified. For the wrong-CN negative test use a deliberately incorrect name and OVPN_EXTERNAL_EXPECT=connect:certificate_verification_failure. Do not publish raw exports, private keys or account credentials.

## Access Server accelerated rekey comparison (2026-11-27)

Fresh user-locked TLS-crypt profile, Access Server 3.2.4, private lab echo host. The Go client completed two 5-second UDP rekeys and three echoes in one generation. UDP at 15 seconds and TCP at 5 and 15 seconds installed key 1 but failed subsequent echo. TCP at 5 seconds additionally failed the next reset and reconnected.

The bundled 2.7.7as0 reference client used an isolated real TUN and the same private target, with forced intervals and continuous ICMP:

| Transport | Interval | Replies / sent | Initializations | Soft resets |
|---|---:|---:|---:|---:|
| UDP | 5s | 7/17 | 1 | 3 |
| UDP | 15s | 29/37 | 1 | 2 |
| TCP | 5s | 0/17 | 2 | 4 |
| TCP | 15s | 15/37 | 2 | 2 |

TCP 15s returned only the first 15 echoes; UDP had gaps around rotation. TCP 5s failed even initial echo, so it cannot establish a post-rekey comparison. These observations show loss/reconnect is not unique to Go under accelerated rekey, but do not identify the cause or establish normal-interval TCP rekey correctness. No security policy was weakened and no speculative protocol fix was made. The original AS routing was restored.
