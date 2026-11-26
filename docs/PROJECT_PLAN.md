# Product plan: OpenVPN Go

**Project status:** planning and scaffold  
**Working name:** OpenVPN Go  
**Proposed module:** github.com/hamedsanaei/openvpn-go (provisional)  
**Target:** an independently implemented, modular OpenVPN client library in Go  
**Primary integration:** a future 3x-ui/Xray outbound adapter  
**License:** MIT (selected; see LICENSE and docs/LICENSE_RESEARCH.md)  
**Release target:** v0.1.0-beta only after interoperability and security gates pass

## 1. Product vision

Deliver a dependable Go library that implements the OpenVPN client protocol and can be embedded by other Go applications. The protocol core must remain independent of 3x-ui, Xray, operating-system TUN drivers and any single transport provider.

The first product is a client engine, not a server and not a complete VPN desktop application. It accepts a packet-oriented tunnel endpoint, establishes an authenticated OpenVPN session to one of a set of configured remotes, protects packets and exposes lifecycle, statistics and failure information to its caller.

## 2. Why a new implementation

The legacy repository is MPL-2.0. This project is intended to have its own identity and a permissive license. Therefore the new implementation must not copy, translate, mechanically port or adapt implementation code, tests, comments, fixtures or documentation from that repository.

The protocol behavior will be specified from public OpenVPN documentation and standards, then independently implemented and tested against real OpenVPN servers. See CLEAN_ROOM.md for an important limitation: previous work in this ChatGPT context has inspected and modified the legacy source, so formal legal clean-room separation cannot be claimed for implementation by that same already-exposed contributor. A separate implementation contributor with no access to the legacy source is required if formal clean-room separation is a hard legal requirement.

## 3. Product goals

1. Correct OpenVPN TLS-mode client interoperability.
2. Strict authentication and secure defaults.
3. UDP and TCP transport support.
4. Robust remote selection, failover and reconnect.
5. A small, stable packet-oriented public API.
6. A profile parser that reports unsupported directives clearly.
7. Testability through deterministic transports and a real-server matrix.
8. Integration into 3x-ui without importing panel-specific dependencies into the core.
9. Low resource overhead and bounded memory/queues.
10. Independent releases, versioning, documentation and governance.

## 4. Non-goals for v0.x

- OpenVPN server mode.
- TAP / Ethernet bridging.
- Legacy compression or packet compression.
- Obsolete key method 1 unless a verified deployment requires it.
- Weak, obsolete or non-AEAD data ciphers.
- OS route, firewall or DNS mutation inside the protocol core.
- A built-in GUI or management daemon.
- A hard dependency on 3x-ui, Xray, OpenSSL or cgo.

## 5. Required capabilities to preserve

- UDP and TCP, with correct OpenVPN TCP stream framing.
- Multiple remote entries, per-remote protocol/port and remote-random behavior.
- Connection profiles and remote failover.
- Per-endpoint TLS identity/SNI and certificate verification.
- Client certificate/private-key authentication.
- Username/password authentication when requested by the profile.
- Inline and external CA/certificate/key material.
- tls-auth, tls-crypt and tls-crypt-v2.
- AEAD data-channel negotiation, packet protection and replay defense.
- Control-channel reliability, ACK/retransmission and packet sequencing.
- Key generation rollover/rekey and keepalive behavior.
- Context cancellation, bounded timeouts, reconnect backoff and graceful shutdown.
- Custom transport integration points for future proxy or obfuscation adapters.
- Safe statistics and structured logs that never expose credentials or key material.
- A packet API suitable for TUN adapters and Xray/3x-ui integration.

## 6. Architecture summary

Public packages:
- client: client lifecycle, options, state, statistics and endpoint status.
- profile: OVPN parsing, validation and diagnostics.
- transport: packet transport contract and standard UDP/TCP implementations.
- tunnel: packet-oriented interface supplied by the embedding application.

Internal packages:
- wire: packet headers, opcodes, key IDs and stream framing.
- control: control-channel packets, ACKs, reliability and replay windows.
- tlscontrol: TLS session, certificate identity and control-channel protection.
- data: data-channel packet formats, AEAD and replay handling.
- crypt: protocol key derivation and cipher adapters; never invent primitives.
- session: handshake and established-session state machine.
- failover: endpoint ordering, retry policy and backoff.
- observability: redacted logs, metrics and event types.
- testkit: deterministic fake transports and test helpers.

The 3x-ui/Xray adapter lives outside the core package graph.

## 7. Security and compatibility policy

- Certificate chain and server identity validation are mandatory by default.
- No implicit InsecureSkipVerify path.
- Unsupported security-sensitive profile directives produce an actionable error.
- Compression and weak legacy ciphers are not enabled.
- Packet sizes, parser depth, queues, retries and buffers are bounded.
- All replay windows and packet counters are tested at boundaries and rollover.
- OpenVPN's published wire-protocol document is treated as a technical reference, not the sole conformance authority; it is marked work-in-progress. Validate behavior against official OpenVPN releases and the official manual.

## 8. Definition of done for a release

A release cannot be called production-ready until:
- the requirement traceability matrix has no unexplained MUST gaps;
- all unit, race, fuzz-smoke and static checks pass;
- interoperability tests pass against the declared OpenVPN version matrix;
- certificate identity, replay protection and key rollover tests pass;
- security review has no unresolved critical/high finding;
- dependency and license inventory is complete;
- docs explain supported and unsupported directives;
- the 3x-ui integration has an end-to-end test or a documented reason it is deferred;
- the release artifact is reproducible and tagged with a changelog.

## 9. Project controls

- Requirements are tracked by IDs in REQUIREMENTS.md.
- Work is tracked in TASKS.md and grouped by MILESTONES.md.
- Architecture decisions are recorded in docs/adr/.
- Every feature has tests and a traceability link to a requirement.
- Every external dependency has a license and maintenance review.
- No remote GitHub repository is created until the owner confirms the project name and the provenance review is ready.

## 10. Immediate next steps

1. Verify the MIT copyright holder details before public release.
2. Confirm whether formal clean-room separation is required. If yes, appoint an implementation contributor who has not accessed the legacy source.
3. Install and pin the Go toolchain; the current development host did not have a Go executable in PATH during scaffold creation.
4. Review the protocol requirements and compatibility targets.
5. Start M0 and do not implement protocol code before the protocol baseline and threat model are approved.
