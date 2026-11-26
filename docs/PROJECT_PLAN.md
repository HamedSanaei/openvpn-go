# Product plan: OpenVPN Go

- **Project status** · M6 and M7 engineering work verified, independent review pending
- **Project name** · OpenVPN Go
- **Module** · `github.com/hamedsanaei/openvpn-go`
- **Target** · An independently implemented, modular OpenVPN client library in Go
- **Primary integration** · A Linux 3x-ui/Xray egress adapter
- **License** · [MIT](../LICENSE)
- **Release target** · v0.1.0-beta after interoperability and security gates pass

## 1. Product vision

Deliver a dependable Go library that implements the OpenVPN client protocol and can be embedded by other Go applications. The protocol core must remain independent of 3x-ui, Xray, operating-system TUN drivers and any single transport provider.

The first product is a client engine, not a server and not a complete VPN desktop application. It accepts a packet-oriented tunnel endpoint, establishes an authenticated OpenVPN session to one of a set of configured remotes, protects packets and exposes lifecycle, statistics and failure information to its caller.

## 2. Why a new implementation

The legacy repository is MPL-2.0. This project is intended to have its own identity and a permissive license. Therefore the new implementation must not copy, translate, mechanically port or adapt implementation code, tests, comments, fixtures or documentation from that repository.

The protocol baseline uses public OpenVPN documentation and standards.
The owner approved spec-driven independent development. Maintain the
separation and prior-exposure disclosure and validate the implementation
against the approved reference server.
[Source separation](CLEAN_ROOM.md) · [M0 decision](adr/0006-m0-governance-and-scope.md)

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
- The compatibility matrix pins OpenVPN Community 2.6.23. The protocol baseline uses OpenVPN's draft, the official manual and version-specific corroboration. Validate behavior against the pinned release. [Compatibility matrix](COMPATIBILITY_MATRIX.md) · [Protocol baseline](PROTOCOL_BASELINE.md)

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
- The confirmed GitHub origin is `HamedSanaei/openvpn-go`. The legacy reference is frozen in the provenance ledger and stays outside this repository.

## 10. Beta candidate

The Go client authenticates the OpenVPN control session, derives keys and
exchanges IP traffic with the pinned peer. M4 validates OVPN profiles and
their file references and preserves each remote's connection settings.
M5 adds cancellable fallback and reconnect with redacted lifecycle
statistics. M6 records platform, interoperability and security evidence.
M7 connects the Linux host tunnel to the stock Xray outbound. The beta
release requires the independent security, provenance and license reviews.
[Hardening evidence](HARDENING.md) · [Release policy](RELEASE.md)
[Delivery gates](MILESTONES.md) · [Engineering work](TASKS.md)
