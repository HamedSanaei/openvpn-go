# Compatibility matrix

Status: planned; no interoperability result has been claimed yet.

| OpenVPN peer | Transport | TLS mode | Authentication | Data channel | Status |
|---|---|---|---|---|---|
| OpenVPN 2.6.x (pinned patch release to select in M0) | UDP | TLS | Client certificate | AEAD | Planned |
| OpenVPN 2.6.x (pinned patch release to select in M0) | TCP | TLS | Client certificate | AEAD | Planned |
| OpenVPN 2.6.x (pinned patch release to select in M0) | UDP/TCP | TLS | Certificate + username/password | AEAD | Planned |
| OpenVPN 2.6.x (pinned patch release to select in M0) | UDP/TCP | tls-auth | Both supported auth modes | AEAD | Planned |
| OpenVPN 2.6.x (pinned patch release to select in M0) | UDP/TCP | tls-crypt | Both supported auth modes | AEAD | Planned |
| OpenVPN 2.6.x (pinned patch release to select in M0) | UDP/TCP | tls-crypt-v2 | Both supported auth modes | AEAD | Planned |

## Rules

- Replace planned rows with exact tested server build, OS, TLS version, negotiated cipher and test result.
- Do not use "OpenVPN compatible" as a blanket claim if only a subset of modes has been tested.
- Record unsupported directives and known interoperability gaps in release notes.
- Expand the matrix only when automated or reproducible manual test evidence exists.
