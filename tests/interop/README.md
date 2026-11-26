# OpenVPN interoperability tests

This directory will contain integration tests against disposable, pinned OpenVPN server versions.

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

The initial server matrix will be selected in M0 and recorded in docs/COMPATIBILITY_MATRIX.md.
