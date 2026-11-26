# Milestones and delivery gates

Estimates are for one experienced Go engineer after the scope and clean-room process are approved. They are planning ranges, not delivery promises. Protocol research or interoperability surprises can extend them.

## M0 — Governance, requirements and protocol specification
**Status:** Complete on 2026-11-26.

- [x] Owner approved product scope, MIT license and patent policy. [Decision record](adr/0006-m0-governance-and-scope.md)
- [x] Owner resolved formal clean-room separation and contributor requirements. [Source separation](CLEAN_ROOM.md)
- [x] Every requirement, including all MUST requirements, has a planned acceptance test or review and a milestone. [Acceptance criteria](TEST_STRATEGY.md) · [Task mapping](TASKS.md#requirement-mapping)
- [x] The OpenVPN reference version and modes are declared. Packet layouts, state transitions, threat controls and provenance have been specified. [Compatibility matrix](COMPATIBILITY_MATRIX.md) · [Protocol baseline](PROTOCOL_BASELINE.md) · [Security model](SECURITY_MODEL.md) · [Provenance ledger](PROVENANCE.md)
- [x] Go 1.26.11 pinned. Formatting, `go test ./...` and `go vet ./...` passed on Windows amd64 and Linux amd64. `go test -race ./...` passed on Linux amd64. The scaffold has no Go test files. Actionlint 1.7.11 passed on the revised workflow. The hosted CI run verifies the original scaffold revision. The M0 Go steps ran locally with the new pin. [Module](../go.mod) · [Workflow](../.github/workflows/ci.yml) · [Scaffold CI run](https://github.com/HamedSanaei/openvpn-go/actions/runs/45817778587)

## M1 — Foundation and public API
**Status:** Complete on 2026-11-26.

- [x] API review covers configuration, redacted errors, endpoint identity and ownership of the transport, session and tunnel. An external-package test exercises the public entry point. [API contract](ARCHITECTURE.md#m1-public-api) · [Public API test](../client/public_test.go)
- [x] UDP loopback and TCP framing tests pass on Windows amd64 and Linux amd64. Scenarios include truncated and oversized frames, short buffers, partial I/O and socket closure. [Transport tests](../transport/transport_test.go) · [TCP tests](../transport/tcp_test.go)
- [x] Deterministic cancellation and concurrent Close tests pass. Close waits for pending dials and forwarding workers, and tests verify that owned resources close once. [Lifecycle tests](../client/client_test.go)
- [x] Formatting, `go test ./...`, `go test -race ./...`, `go vet ./...` and a cgo-free build pass with the pinned Go version. The full check set ran locally on Linux amd64 and the workflow passed Actionlint. The updated workflow will run on a pull request. [CI workflow](../.github/workflows/ci.yml)
- [x] GitHub main requires a pull request and the Go CI check. Force pushes and deletion are disabled. [Branch protection](https://github.com/HamedSanaei/openvpn-go/settings/branches)

## M2 — Control channel and TLS
**Status:** Complete on 2026-11-26.

- [x] The authenticated control handshake passes against OpenVPN Community 2.6.23 on UDP and TCP. All 20 baseline modes and a focused TLS 1.3 case pass. [Compatibility evidence](COMPATIBILITY_MATRIX.md#evidence-records)
- [x] Certificate chain and server-name failures are terminal. Unit tests also reject expired and not-yet-valid certificates. A wrong password returns a redacted authentication failure. [TLS tests](../internal/tlscontrol/handshake_test.go) · [Interop suite](../tests/interop/control_test.go)
- [x] ACK, retransmission, replay and ordered delivery tests pass. The pinned server tests also pass after a deliberately dropped reset and reordered control packets. [Reliability tests](../internal/control/reliable_test.go)
- [x] tls-auth, tls-crypt and tls-crypt-v2 pass on both transports with client certificate and certificate-plus-password authentication. The v2 suite includes a forced cookie exchange and a wire fixture for the no-cookie path. [Compatibility matrix](COMPATIBILITY_MATRIX.md) · [v2 fixtures](../internal/control/reliable_test.go)

The verified TLS control session supplies the negotiated parameters and
exporter material consumed by M3.

## M3 — Data channel and cryptography
**Status:** Complete on 2026-11-26.

- [x] Go and OpenSSL return the same 256 exporter bytes in TLS 1.2 and 1.3. Independent nonce and DATA_V2 vectors match in both directions for every supported cipher. [Exporter test](../tests/interop/exporter_test.go) · [Vector tests](../internal/data/channel_test.go)
- [x] AEAD tampering, truncation, invalid IDs, replay and packet-usage tests pass. Only authenticated keepalives and valid IP packets refresh liveness. [Data tests](../internal/data/channel_test.go) · [Liveness test](../internal/session/session_test.go)
- [x] Bidirectional UDP traffic through the tunnel passes all 120 IPv4 scenarios with OpenVPN 2.6.23. The suite also covers IPv6 over IPv6 transport. [Compatibility evidence](COMPATIBILITY_MATRIX.md#evidence-records)
- [x] Both endpoints initiate rekey successfully. Live traffic passes after rollover from key ID 7 to 1. Deterministic tests cover overlap, old-key expiry and rejection of a prior generation using a reused ID. [Rekey tests](../tests/interop/data_test.go) · [Generation tests](../internal/data/channel_test.go)

## M4 — Profile parser and configuration
**Status:** Complete on 2026-11-26.

**Deliverable:** OVPN parser, inline/external material, connection blocks, per-remote settings and diagnostics.

Exit gate:
- [x] Every supported directive has valid and malformed parser test cases and a documentation entry. [Registry](PROFILE.md#directive-registry) · [Parser tests](../profile/parse_test.go)
- [x] Unsupported security-sensitive directives fail with redacted diagnostics. Unit tests cover profile and material limits, and the profile fuzz target passed a 30-second run on Linux amd64. [Security acceptance](SECURITY_MODEL.md) · [Fuzz target](../profile/parse_test.go)
- [x] Root-based resolution stays confined and rejects traversal, device paths, symlink escapes and non-regular files. [Resolver](../profile/material.go) · [Filesystem tests](../profile/parse_test.go)
- [x] Ten generated inline UDP and external TCP profiles parse and connect to OpenVPN Community 2.6.23. Negative tests verify certificate rejection before credentials and a redacted wrong-password failure. [Compatibility evidence](COMPATIBILITY_MATRIX.md#evidence-records)

## M5 — Failover, reconnect and observability
**Status:** Complete on 2026-11-26.

**Deliverable:** endpoint selection, remote-random, retry/backoff, custom transport, reconnect and safe stats.

Exit gate:
- [x] A silent UDP candidate falls back to TCP. A live tunnel switches to UDP after TCP loss and returns to the restarted TCP server. Packets pass in both directions after each transition. [Interop evidence](COMPATIBILITY_MATRIX.md#evidence-records)
- [x] Mixed-endpoint tests capture SNI and verify separate TLS identities and session tokens. Wrong name, CA and password stop the attempt sequence. [Interop tests](../tests/interop/failover_test.go)
- [x] Tests use virtual time to verify attempt bounds, jitter, cancellation and cleanup while waiting to reconnect. [Retry tests](../client/retry_test.go)
- [x] The client exposes redacted, bounded events and aggregate statistics. Tests cover event overwrite and concurrent lifecycle snapshots. [Lifecycle contract](LIFECYCLE.md) · [Observability tests](../client/retry_test.go)

## M6 — Interoperability, security and performance hardening
**Status:** Engineering checks passed on 2026-11-26. Independent review is pending.

**Deliverable:** expanded server matrix, fuzz/race/performance evidence, dependency inventory and independent review.

Exit gate:
- [x] Full declared interop suites pass against OpenVPN 2.6.22 and 2.6.23. [Compatibility evidence](COMPATIBILITY_MATRIX.md#evidence-records)
- [ ] Independent reviewer confirms no unresolved critical or high security findings. [Review status](HARDENING.md#supply-chain-and-review)
- [x] Fuzz and race checks pass. [Campaign and shutdown evidence](HARDENING.md#fuzz-and-shutdown-coverage)
- [x] Performance baselines and regression thresholds are recorded. [Performance budgets](HARDENING.md#performance-budgets)
- [x] SPDX inventory and dependency license checks pass. [Supply-chain evidence](HARDENING.md#supply-chain-and-review)

## M7 — 3x-ui/Xray integration and beta release
**Status:** Adapter and beta candidate are ready. Independent sign-off, tagging and publication are pending.

**Deliverable:** isolated integration adapter, examples, documentation, release workflow and v0.1.0-beta.

Exit gate:
- [x] The adapter uses public core packages and the stock Xray outbound boundary. [Integration ADR](adr/0007-xray-linux-egress.md)
- [x] TCP and UDP traffic pass before and after peer restart. Cancellation joins the adapter and a missing interface fails closed. [Live test](../tests/interop/xray_test.go)
- [x] Candidate release notes record verified modes and limitations. [Changelog](../CHANGELOG.md) · [Release policy](RELEASE.md)
- [ ] An independent reviewer signs off on the license and provenance of the exact tagged revision. [Release gate](CLEAN_ROOM.md#release-gate)
- [x] The beta is scoped to integration and operational evaluation. [Release policy](RELEASE.md)

## Overall planning range

Approximately **6–10 weeks** for a careful single-engineer implementation with real interoperability testing. A narrower UDP/TCP + TLS + AEAD MVP may be delivered earlier, but it must not be presented as full OpenVPN compatibility.
