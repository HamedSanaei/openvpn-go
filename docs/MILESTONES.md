# Milestones and delivery gates

Estimates are for one experienced Go engineer after the scope and clean-room process are approved. They are planning ranges, not delivery promises. Protocol research or interoperability surprises can extend them.

## M0 — Governance, requirements and protocol specification
**Estimate:** 2–4 working days  
**Deliverable:** approved scope, requirement IDs, threat model, license decision, provenance process and protocol design notes.

Exit gate:
- [ ] Owner approves product scope and license.
- [ ] Formal clean-room requirement is decided and contributor separation is resolved.
- [ ] Every MUST requirement has an acceptance test plan.
- [ ] Supported OpenVPN versions and profile modes are declared.

## M1 — Foundation and public API
**Estimate:** 3–5 working days  
**Deliverable:** compilable Go module, public Config/Client/Transport/Tunnel contracts, typed errors, lifecycle model, CI and deterministic testkit.

Exit gate:
- [ ] API review complete.
- [ ] UDP packet transport and TCP framing unit tests pass.
- [ ] Cancellation and Close tests prove no goroutine leaks.
- [ ] go test, race, vet and formatting pass.

## M2 — Control channel and TLS
**Estimate:** 1–2 weeks  
**Deliverable:** packet codec, control state machine, TLS handshake, peer identity validation, auth sequence and control reliability.

Exit gate:
- [ ] Control handshake works against pinned test server.
- [ ] Certificate chain/name failures are terminal and tested.
- [ ] ACK/retransmit/replay tests pass under loss and reordering.
- [ ] tls-auth and tls-crypt interop passes.

## M3 — Data channel and cryptography
**Estimate:** 1–2 weeks  
**Deliverable:** key derivation, AEAD data packet formats, replay protection, key IDs and rekey.

Exit gate:
- [ ] Independent vectors validate derivation and nonce construction.
- [ ] AEAD tampering/replay tests pass.
- [ ] Bidirectional data packets pass against the compatibility matrix.
- [ ] Rekey overlap and key-ID rollover are tested.

## M4 — Profile parser and configuration
**Estimate:** 4–7 working days  
**Deliverable:** OVPN parser, inline/external material, connection blocks, per-remote settings and diagnostics.

Exit gate:
- [ ] Every supported directive has parser tests and docs.
- [ ] Unsupported security-sensitive directives fail explicitly.
- [ ] No path traversal or unsafe file access from referenced profile files.
- [ ] Real profiles from generated fixtures parse and connect.

## M5 — Failover, reconnect and observability
**Estimate:** 3–6 working days  
**Deliverable:** endpoint selection, remote-random, retry/backoff, custom transport, reconnect and safe stats.

Exit gate:
- [ ] Mixed UDP/TCP remotes fail over correctly.
- [ ] Endpoint-specific SNI/certificate validation survives every retry.
- [ ] Cancellation stops retries promptly.
- [ ] Metrics and logs are redacted and bounded.

## M6 — Interoperability, security and performance hardening
**Estimate:** 1–2 weeks  
**Deliverable:** expanded server matrix, fuzz/race/performance evidence, dependency inventory and independent review.

Exit gate:
- [ ] All declared interoperability scenarios pass.
- [ ] No unresolved critical/high security findings.
- [ ] Fuzz and race gates pass.
- [ ] Performance baseline and regression thresholds are documented.
- [ ] SPDX/SBOM and dependency license checks pass.

## M7 — 3x-ui/Xray integration and beta release
**Estimate:** 4–7 working days  
**Deliverable:** isolated integration adapter, examples, documentation, release workflow and v0.1.0-beta.

Exit gate:
- [ ] Adapter uses only public API.
- [ ] End-to-end traffic and shutdown tests pass.
- [ ] Release notes list supported modes and limitations.
- [ ] License and provenance review is signed off.
- [ ] No production-readiness claim until operational validation is complete.

## Overall planning range

Approximately **6–10 weeks** for a careful single-engineer implementation with real interoperability testing. A narrower UDP/TCP + TLS + AEAD MVP may be delivered earlier, but it must not be presented as full OpenVPN compatibility.
