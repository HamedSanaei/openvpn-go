# Engineering task register

Tasks are intentionally written before implementation. Mark an item complete only when its acceptance evidence exists. Link code changes and tests in the eventual issue/PR.

## M0 — Governance and specification

- [x] M0-001 Confirm project/repository name and module path. [Identity decision](adr/0006-m0-governance-and-scope.md)
- [x] M0-002 Select final license and approve patent policy. [MIT decision](adr/0005-license-selection.md)
- [x] M0-003 Decide whether formal legal clean-room separation is mandatory. [Owner decision](adr/0006-m0-governance-and-scope.md)
- [x] M0-004 Resolve contributor separation. An isolated appointment is inapplicable under the approved process. [Source separation](CLEAN_ROOM.md)
- [x] M0-005 Freeze the legacy reference separately. [Pinned public revision](PROVENANCE.md#frozen-legacy-reference)
- [x] M0-006 Approve OpenVPN server scope and client modes. [Scope decision](adr/0006-m0-governance-and-scope.md) · [Pinned compatibility matrix](COMPATIBILITY_MATRIX.md)
- [x] M0-007 Complete protocol packet and state specifications using public references. [Protocol baseline](PROTOCOL_BASELINE.md)
- [x] M0-008 Complete the threat model and security acceptance checklist. [Security model](SECURITY_MODEL.md)
- [x] M0-009 Establish the provenance ledger and dependency policy. [Provenance ledger](PROVENANCE.md)
- [x] M0-010 Review requirement-to-test traceability for every requirement. [Acceptance criteria](TEST_STRATEGY.md) · [Task mapping](#requirement-mapping)

## M1 — Foundation and API

- [x] M1-001 Verify Git initialization and protect main. Pull requests and the GitHub Actions check are required, including for administrators. [Branch protection](https://github.com/HamedSanaei/openvpn-go/settings/branches)
- [x] M1-002 Install and pin the Go toolchain and verify the module. [Go module](../go.mod)
- [x] M1-003 Define Config, Endpoint, ClientState and redacted typed errors. [API contract](ARCHITECTURE.md#m1-public-api)
- [x] M1-004 Define packet transport and ownership semantics. [Transport contract](../transport/transport.go)
- [x] M1-005 Define the packet tunnel and lifecycle semantics. [Tunnel contract](../tunnel/tunnel.go)
- [x] M1-006 Implement UDP packet transport. [UDP adapter](../transport/udp.go) · [Loopback tests](../transport/transport_test.go)
- [x] M1-007 Implement TCP length-prefixed packet transport. [TCP adapter](../transport/tcp.go) · [Framing tests](../transport/tcp_test.go)
- [x] M1-008 Bound transport frames and forwarding buffers. [Transport limits](../transport/transport.go) · [Forwarding](../client/run.go)
- [x] M1-009 Add an in-memory packet transport and manual test clock. [Test transport](../internal/testkit/packet.go) · [Manual clock](../internal/testkit/clock.go)
- [x] M1-010 Verify formatting, cgo-free build, test, race and vet gates. [CI workflow](../.github/workflows/ci.yml)

## M2 — Wire and control plane

- [x] M2-001 Specify and decode opcode/key IDs. [Wire codec](../internal/wire/control.go)
- [x] M2-002 Bound control header, ACK and payload parsing. [Wire tests](../internal/wire/control_test.go)
- [x] M2-003 Scope session IDs and reliable counters to the control session. [Protocol baseline](PROTOCOL_BASELINE.md) · [Reliable channel](../internal/control/reliable.go)
- [x] M2-004 Encode and decode control packets. [Wire codec](../internal/wire/control.go)
- [x] M2-005 Parse, aggregate and validate ACKs. [Reliability tests](../internal/control/reliable_test.go)
- [x] M2-006 Implement bounded UDP retransmission and timers. [Reliable channel](../internal/control/reliable.go)
- [x] M2-007 Enforce the protected outer replay window. [Replay window](../internal/control/replay.go)
- [x] M2-008 Sequence reset, TLS, key method 2 and authenticated push. [Client stages](ARCHITECTURE.md#m2-control-session)
- [x] M2-009 Carry TLS over the reliable packet transport. [Control stream](../internal/control/stream.go)
- [x] M2-010 Verify trust chains, certificate validity and the configured server name. [TLS tests](../internal/tlscontrol/handshake_test.go)
- [x] M2-011 Load and use the client certificate/key pair. [TLS configuration](../internal/tlscontrol/config.go)
- [x] M2-012 Exchange optional credentials inside verified TLS and return redacted errors. [Key method 2](../internal/tlscontrol/keymethod.go) · [Client API](../client/control.go)
- [x] M2-013 Implement directional tls-auth with an approved HMAC digest. [Control protection](../internal/control/protection.go)
- [x] M2-014 Implement tls-crypt and verify authentication before accepting clear payloads. [Control protection](../internal/control/protection.go)
- [x] M2-015 Parse tls-crypt-v2 client keys and handle wrapped-key continuation. Preserve server-owned metadata as opaque bytes. [v2 tests](../internal/control/reliable_test.go)
- [x] M2-016 Exercise against the pinned peer under loss, reordering and authentication failures. [Interop tests](../tests/interop/control_test.go)

## M3 — Data plane and crypto

- [x] M3-001 Derive data keys with verified TLS key material export and the directional OpenVPN layout. [Exporter](../internal/crypt/data.go)
- [x] M3-002 Generate independent TLS 1.2 and 1.3 exporter and packet vectors. [Generator](../internal/data/testdata/generate_vectors.py) · [Vector tests](../internal/data/channel_test.go)
- [x] M3-003 Enforce the supported AEAD cipher offer and authenticated negotiation. [Allow-list](../internal/crypt/data.go) · [Negotiation](../internal/tlscontrol/push.go)
- [x] M3-004 Implement AES-128-GCM and AES-256-GCM DATA_V2 packets. [Data channel](../internal/data/channel.go)
- [x] M3-005 Implement ChaCha20-Poly1305 using the pinned Go module. [Dependency record](PROVENANCE.md)
- [x] M3-006 Enforce packet IDs, nonce limits and per-generation replay protection. [Replay window](../internal/data/replay.go)
- [x] M3-007 Select negotiated generations by key ID and wrap from 7 to 1. [Generation logic](../internal/data/channel.go)
- [x] M3-008 Rekey from either endpoint and allow bounded old-key receive overlap. [Session lifecycle](../internal/session/rekey.go)
- [x] M3-009 Cover tampering, truncation, replay, key limits and rollover. [Data tests](../internal/data/channel_test.go)
- [x] M3-010 Pass bidirectional traffic and rekey tests against OpenVPN 2.6.23. [Interop evidence](COMPATIBILITY_MATRIX.md#evidence-records)

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

## Requirement mapping

The IDs below refer to the [requirements](REQUIREMENTS.md) and their
[acceptance criteria](TEST_STRATEGY.md). Use the listed requirements when
recording test evidence for a task.

| Tasks | Requirement IDs |
|---|---|
| M1-001–M1-002, M1-010 | NFR-002, NFR-009 |
| M1-003–M1-005 | FR-017, FR-019, FR-020, NFR-001, NFR-004 |
| M1-006–M1-009 | FR-002, FR-003, FR-017, SEC-003, SEC-005, SEC-010 |
| M2-001–M2-003 | FR-004, FR-010, SEC-003 |
| M2-004–M2-007 | FR-005, FR-010, SEC-004, SEC-005 |
| M2-008–M2-012 | FR-001, FR-005–FR-008, SEC-001, SEC-002 |
| M2-013–M2-016 | FR-005, FR-006, FR-009, FR-010, SEC-001, SEC-004 |
| M3-001–M3-005 | FR-011, FR-013, SEC-006–SEC-008 |
| M3-006–M3-010 | FR-011–FR-013, FR-020, SEC-004, SEC-008, NFR-006 |
| M4-001–M4-004 | FR-014, FR-015, FR-023, NFR-007 |
| M4-005–M4-010 | FR-006, FR-008, FR-009, FR-014, FR-023, SEC-001, SEC-003, SEC-005, SEC-006 |
| M5-001–M5-004 | FR-015, FR-016, FR-018, SEC-009 |
| M5-005–M5-010 | FR-017–FR-021, SEC-002, SEC-005, SEC-010, NFR-006 |
| M6-001–M6-006 | SEC-003, SEC-005, SEC-010, NFR-002, NFR-003, NFR-005, NFR-006, NFR-009 |
| M6-007–M6-010 | SEC-007, NFR-008–NFR-010 |
| M7-001–M7-005 | FR-019, FR-020, FR-022, SEC-009, SEC-010, NFR-001, NFR-004 |
| M7-006–M7-008 | NFR-008–NFR-010 |
