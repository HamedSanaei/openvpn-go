# Pritunl profile import

The opt-in policy supports the verified Pritunl 1.34.4822.59 inline export shape. Separate lab results cover the real Pritunl service and a generated-profile matrix using Community OpenVPN. [Pritunl server qualification](SERVER_INTEROP.md#pritunl-134482259-2026-11-27)

Explicitly supply the administrator-verified **VPN server certificate common name**, not the web interface hostname or an unverified value copied from the profile:

- Go: `profile.Options{PritunlServerName: verifiedName}`
- CLI: `ovpn-inspect -pritunl-server-name NAME profile.ovpn` or the corresponding `ovpn-xray` flag.
- Authorized external probe: `OVPN_EXTERNAL_PRITUNL_SERVER_NAME=NAME` with the existing external profile harness.

The importer requires an inline or authorized referenced CA and client identity, server role verification, and an explicit AEAD offer. It rejects mixed provider policies and password-only import. The exact AES-GCM/CBC fallback pairs emitted by the exporter are reduced to AES-GCM; CBC-only and unrecognized combinations remain rejected. The advisory CBC cipher must match the remaining GCM cipher. No arbitrary unknown options, scripts, or environment assignments are executed.

The 30-day exported renegotiation interval is capped at seven days, with a warning. Local ping/ping-restart, socket buffer, verbosity, peer-info, device metadata, and Windows DNS hints are validated and reported as ignored; the authenticated pushed timers drive the tunnel and host DNS/routing remains the embedding application's responsibility. The importer does not provide host DNS leak protection or Pritunl-specific metadata/device authentication. Standard certificate/password TLS auth can be configured through the existing API; SSO, PIN/OTP, device authorization, sync APIs and proprietary client authentication have not been qualified. A Pritunl export can contain sensitive metadata, so never publish raw exports.

Generated profile tests cover AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, malicious directives, CBC-only rejection and strict name policy. The separate Linux test `TestPritunlShapedCommunityInterop` uses a native Community peer, generated credentials and certificates, and verifies bidirectional tunnel data for the same shape. It is not a live Pritunl control-plane test.


## Generated-profile reference results (2026-11-27)

On Ubuntu 26.04 amd64, in a disposable network namespace with no public listener, OpenVPN Community 2.7.0 (OpenSSL 3.5.5, SHA-256 06d101129eec1816fe2f79910c292a33da2779e06e073dbc4de295ad6dc93ff6) passed six generated Pritunl-shaped profile cases. All used TLS 1.3, tls-auth, a generated client certificate and synthetic password, and bidirectional UDP payload via a real server TUN.

| Transport | AES-128-GCM | AES-256-GCM | ChaCha20-Poly1305 |
|---|---|---|---|
| TCP | PASS | PASS | PASS |
| UDP | PASS | PASS | PASS |

The full Windows Go test suite also passed. This generated-profile matrix used a Community peer. The separate real-service lab covers original certificate-only exports and selected negotiated ciphers and rekeys. [Real Pritunl results](SERVER_INTEROP.md#pritunl-134482259-2026-11-27)
