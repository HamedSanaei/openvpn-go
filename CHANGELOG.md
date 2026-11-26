# Changelog

## Unreleased

- Explicit password-only client authentication with verified server trust.
- Redacted, line-numbered profile capability reports.
- Authenticated address, route, gateway, MTU and DNS snapshots with push policy.
- Transactional tunnel setup on reconnect and generation-bound Xray DNS sockets.
  [Tunnel and DNS contracts](docs/TUNNEL.md)

## v0.1.0-beta

- Embeddable OpenVPN TLS client with UDP and framed TCP transport, verified
  certificates, optional username/password, tls-auth, tls-crypt and tls-crypt-v2.
- AEAD-only DATA_V2 with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305,
  replay protection, keepalives and rekey.
- OVPN profile parsing with inline or confined external material, ordered
  connection profiles, TLS identity policies and redacted diagnostics.
- Configurable failover and reconnect, cancellation, custom dialers and
  bounded redacted telemetry.
- Linux Xray egress adapter for a preconfigured host TUN and the stock
  Xray `freedom` outbound. The adapter keeps assigned tunnel addresses
  pinned through reconnect.
- Verified OpenVPN reference peers are Community 2.6.22 and 2.6.23.
  The Xray integration target is 26.10.21. The beta scope is TLS-mode IP
  traffic. See the compatibility matrix and integration guide for bounds.

[Compatibility matrix](docs/COMPATIBILITY_MATRIX.md) · [Xray integration](integrations/xray/README.md) · [Release policy](docs/RELEASE.md)
