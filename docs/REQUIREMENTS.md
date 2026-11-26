# Product and engineering requirements

Requirement keywords MUST, MUST NOT, SHOULD and MAY are normative for this project. Every MUST requirement needs at least one automated test or an explicitly documented manual acceptance test.

The approved client scope and exact initial OpenVPN release are recorded in
the [M0 decision](adr/0006-m0-governance-and-scope.md) and
[compatibility matrix](COMPATIBILITY_MATRIX.md).

## Functional requirements

| ID | Requirement | Initial priority |
|---|---|---|
| FR-001 | Implement OpenVPN TLS-mode client behavior; server mode is out of scope. | MUST |
| FR-002 | Support UDP datagram transport. | MUST |
| FR-003 | Support TCP transport with OpenVPN's 16-bit length-prefixed packet framing. | MUST |
| FR-004 | Multiplex control and data packets and parse opcode/key-id safely. | MUST |
| FR-005 | Establish and maintain the TLS control channel. | MUST |
| FR-006 | Validate certificate chain and server identity by default; support explicit name override and verify-x509-name policy. | MUST |
| FR-007 | Support client certificate/private-key authentication. | MUST |
| FR-008 | Support username/password alongside a client certificate and explicit password-only authentication with verified server identity. | MUST |
| FR-009 | Support tls-auth, tls-crypt and tls-crypt-v2 in the declared compatibility matrix. | MUST, staged by milestone |
| FR-010 | Implement control-channel ACK, retransmission, packet IDs and replay protection. | MUST |
| FR-011 | Negotiate and implement the declared AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 data ciphers. | MUST |
| FR-012 | Implement protocol-correct data packet IDs, replay defense and key generation selection. | MUST |
| FR-013 | Implement key derivation and rekey/renegotiation for the declared compatibility matrix. | MUST |
| FR-014 | Parse OVPN profiles, including inline and external CA/cert/key/auth material. | MUST |
| FR-015 | Support multiple remote entries, remote-random, connection blocks and per-remote proto/port. | MUST |
| FR-016 | Preserve per-endpoint TLS identity and transport settings during failover. | MUST |
| FR-017 | Provide bounded connect/handshake timeouts, context cancellation and graceful Close. | MUST |
| FR-018 | Provide reconnect policy with bounded/unbounded attempt configuration and exponential backoff with jitter. | MUST |
| FR-019 | Expose an injectable packet transport for proxy/custom transport integration. | MUST |
| FR-020 | Expose a packet-oriented API for an external TUN or Xray adapter. | MUST |
| FR-021 | Expose active endpoint, state and redacted connection statistics. | SHOULD |
| FR-022 | Provide an isolated 3x-ui/Xray integration adapter after the core API stabilizes. | MUST for integration milestone |
| FR-023 | Provide explicit parser warnings/errors for unsupported directives; never silently ignore security-sensitive options. | MUST |

## Security requirements

| ID | Requirement | Acceptance evidence |
|---|---|---|
| SEC-001 | TLS peer verification cannot be disabled accidentally by an empty or malformed setting. | Negative tests for hostname, chain, expiry and missing certificate |
| SEC-002 | No credentials, private keys, session keys or raw auth payloads in logs/errors. | Log redaction tests |
| SEC-003 | Packet and profile parsers reject malformed, oversized and truncated input safely. | Fuzzing and boundary tests |
| SEC-004 | Control and data replay windows reject duplicates and stale packet IDs. | Property and replay tests |
| SEC-005 | Queues, buffers, retries and parser nesting have explicit limits. | Load and adversarial tests |
| SEC-006 | No compression or weak legacy data cipher is silently enabled. | Profile validation tests |
| SEC-007 | Cryptographic primitives come from Go standard libraries or reviewed maintained packages. | Dependency and code review |
| SEC-008 | Secret material is not retained longer than needed; best-effort zeroization limitations are documented. | Design review |
| SEC-009 | Endpoint failover does not bypass certificate identity validation. | Multi-endpoint TLS tests |
| SEC-010 | Cancellation and shutdown unblock all goroutines and close owned resources. | Leak/race tests |

## Non-functional requirements

- NFR-001: Public API remains small and versioned; internal packages are not importable by consumers.
- NFR-002: No cgo/OpenSSL runtime dependency in the initial design unless a documented interoperability requirement proves it necessary.
- NFR-003: Linux amd64 and arm64 are primary deployment targets; Windows and macOS are development/test targets.
- NFR-004: Core protocol packages do not create TUN devices or modify host routes.
- NFR-005: Packet processing must avoid unbounded allocations and use benchmarks to guide optimization.
- NFR-006: Concurrent use, Close races and reconnect state transitions must be race-tested.
- NFR-007: Every supported profile directive has a parser test and documentation entry.
- NFR-008: Third-party dependencies must be minimized and have reviewed licenses, security posture and maintenance activity.
- NFR-009: CI runs formatting, unit tests, race detector and go vet; release CI adds fuzz, vulnerability and license checks.
- NFR-010: Compatibility claims must name tested OpenVPN versions and configurations.

## Explicitly deferred or unsupported in v0.x

- Server mode, TAP, bridging and L2 Ethernet.
- Compression directives such as comp-lzo/compress.
- Legacy non-AEAD data ciphers and obsolete key method 1 unless a real compatibility case is approved.
- Scripts, plugins and arbitrary external command execution from profiles.
- Route/DNS mutation and privileged OS configuration.
- Management interface emulation.
- Interactive deferred authentication and SSO.
- Extensions excluded by the initial compatibility matrix.
- Full parity with every OpenVPN directive.

## Traceability rule

Every implementation task must reference one or more requirement IDs. The
[test strategy](TEST_STRATEGY.md) maps every requirement to an acceptance
criterion and a milestone. The [task mapping](TASKS.md#requirement-mapping)
links the engineering work to those criteria. Each MUST requires passing
evidence before its stated delivery gate.
