# Engineering task register

Tasks are intentionally written before implementation. Mark an item complete only when its acceptance evidence exists. Link code changes and tests in the eventual issue/PR.

## M0 — Governance and specification

- [ ] M0-001 Confirm project/repository name and module path.
- [ ] M0-002 Select final license and approve patent policy.
- [ ] M0-003 Decide whether formal legal clean-room separation is mandatory.
- [ ] M0-004 If formal clean-room is mandatory, appoint an implementation contributor isolated from legacy source.
- [ ] M0-005 Freeze legacy repository as a separate reference; do not add it as a remote here.
- [ ] M0-006 Approve supported OpenVPN server versions and client modes.
- [ ] M0-007 Complete protocol packet/state specifications from public references.
- [ ] M0-008 Complete threat model and security acceptance checklist.
- [ ] M0-009 Establish provenance ledger and dependency policy.
- [ ] M0-010 Review requirement-to-test traceability.

## M1 — Foundation and API

- [ ] M1-001 Initialize Git and protect main branch.
- [ ] M1-002 Install/pin Go toolchain and verify go.mod baseline.
- [ ] M1-003 Define public Config, Endpoint, ClientState and typed error API.
- [ ] M1-004 Define packet transport interface and ownership semantics.
- [ ] M1-005 Define packet tunnel interface and lifecycle semantics.
- [ ] M1-006 Implement UDP packet transport.
- [ ] M1-007 Implement TCP length-prefixed packet transport.
- [ ] M1-008 Add bounded buffers and packet-size limits.
- [ ] M1-009 Add deterministic fake transport and test clock.
- [ ] M1-010 Add CI formatting, test, race and vet gates.

## M2 — Wire and control plane

- [ ] M2-001 Specify opcode/key-id encoding and packet header parser.
- [ ] M2-002 Implement bounded packet codec.
- [ ] M2-003 Specify session ID and control packet ID lifecycle.
- [ ] M2-004 Implement control packet encoding/decoding.
- [ ] M2-005 Implement ACK parsing, generation and aggregation.
- [ ] M2-006 Implement retransmit queue with bounded retries and timers.
- [ ] M2-007 Implement control replay window.
- [ ] M2-008 Define explicit client handshake state machine.
- [ ] M2-009 Implement TLS control-channel transport.
- [ ] M2-010 Implement strict CA chain and server-name verification.
- [ ] M2-011 Implement certificate/private-key client authentication.
- [ ] M2-012 Implement username/password exchange and redaction.
- [ ] M2-013 Implement tls-auth.
- [ ] M2-014 Implement tls-crypt.
- [ ] M2-015 Implement tls-crypt-v2 and client key metadata.
- [ ] M2-016 Add packet-loss, reorder and wrong-certificate integration tests.

## M3 — Data plane and crypto

- [ ] M3-001 Specify supported key method and key derivation.
- [ ] M3-002 Create independently generated key-derivation test vectors.
- [ ] M3-003 Implement AEAD cipher negotiation allow-list.
- [ ] M3-004 Implement AES-GCM data packets.
- [ ] M3-005 Implement ChaCha20-Poly1305 where protocol negotiation permits.
- [ ] M3-006 Implement data packet IDs and replay protection.
- [ ] M3-007 Implement key-ID selection and rollover.
- [ ] M3-008 Implement rekey/renegotiation and overlapping key generations.
- [ ] M3-009 Add tamper, replay, truncation and rollover tests.
- [ ] M3-010 Validate bidirectional data traffic against OpenVPN server.

## M4 — Profile parser

- [ ] M4-001 Define supported directive registry and precedence rules.
- [ ] M4-002 Parse client mode, proto, port and remote directives.
- [ ] M4-003 Parse connection blocks and inherited defaults.
- [ ] M4-004 Parse remote-random and per-remote transport options.
- [ ] M4-005 Parse inline CA/cert/key and external file references safely.
- [ ] M4-006 Parse auth-user-pass and key-direction.
- [ ] M4-007 Parse tls-auth, tls-crypt and tls-crypt-v2.
- [ ] M4-008 Parse data-ciphers and TLS verification options.
- [ ] M4-009 Reject or explicitly warn on unsupported security-sensitive directives.
- [ ] M4-010 Add parser fuzzing and fixture coverage.

## M5 — Failover and lifecycle

- [ ] M5-001 Implement deterministic endpoint ordering.
- [ ] M5-002 Implement remote-random without losing fallback candidates.
- [ ] M5-003 Preserve per-endpoint SNI and verification settings.
- [ ] M5-004 Implement retry classification (network vs terminal auth/security).
- [ ] M5-005 Implement bounded connect/handshake timeout.
- [ ] M5-006 Implement exponential backoff with jitter.
- [ ] M5-007 Implement reconnect and active endpoint reporting.
- [ ] M5-008 Implement custom dialer/proxy transport adapter contract.
- [ ] M5-009 Implement graceful shutdown and goroutine leak tests.
- [ ] M5-010 Add structured redacted events and stats.

## M6 — Hardening and release evidence

- [ ] M6-001 Run Linux amd64/arm64 test matrix.
- [ ] M6-002 Add Windows/macOS compile and test jobs.
- [ ] M6-003 Add fuzz targets for profile, framing and packet decoders.
- [ ] M6-004 Run sustained fuzz campaigns and triage findings.
- [ ] M6-005 Run race detector and goroutine leak checks.
- [ ] M6-006 Add benchmarks for throughput, allocations and reconnect.
- [ ] M6-007 Add dependency vulnerability and license scans.
- [ ] M6-008 Generate SPDX SBOM.
- [ ] M6-009 Complete independent security review.
- [ ] M6-010 Publish compatibility matrix and known limitations.

## M7 — 3x-ui/Xray integration and beta

- [ ] M7-001 Inspect the exact target 3x-ui/Xray extension points.
- [ ] M7-002 Define adapter mapping from Xray outbound lifecycle to Client API.
- [ ] M7-003 Implement adapter outside core packages.
- [ ] M7-004 Test packet flow, cancellation, reconnect and shutdown end-to-end.
- [ ] M7-005 Write integration example and deployment notes.
- [ ] M7-006 Finalize license, provenance and contributor policy.
- [ ] M7-007 Create changelog, release workflow and v0.1.0-beta.
- [ ] M7-008 Document upgrade and compatibility policy.
