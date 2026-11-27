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

Access Server 3.2.4 is documented in ACCESS_SERVER.md. Its forced TCP rekey, live inner IPv6 and additional authentication/federation modes remain open. SoftEther stable 4.x, other Developer Edition builds, certificate-only and interactive auth, L2 TAP, CBC, and long-duration/load tests are not qualified. Pritunl and other management panels that deploy Community OpenVPN need separate export and configuration testing; Community protocol tests do not establish panel compatibility. RouterOS CHR 7.25.2 has its existing fixed DATA_V2 evidence, not hardware-wide certification. These are separate compatibility targets; unrelated VPN protocols are not supported by this package.

## Pritunl export shape

An opt-in AEAD-only importer is described in [PRITUNL.md](PRITUNL.md). Six generated export-shaped cases passed native Community 2.7.0 tunnel traffic; the actual Pritunl management/authentication service remains unqualified.
