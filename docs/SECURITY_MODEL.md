# Security model and acceptance gates

This model governs the client scope approved in M0. Tests in M1–M7 provide
implementation evidence. The release gate requires independent review. Follow`r`n[the independent audit plan](INDEPENDENT_AUDIT_PLAN.md) for the scope, methodology,`r`nevidence and external-review gates.
[Scope decision](adr/0006-m0-governance-and-scope.md) · [Acceptance criteria](TEST_STRATEGY.md)

## Assets and assumptions

Protect VPN credentials, auth tokens, client keys, trust anchors, session
secrets, tunnel plaintext, local profile references and traffic metadata.
Preserve authenticated packet delivery, service availability and ownership
of sockets, tunnel handles, timers and goroutines.

Assume an attacker can modify, drop, delay and inject transport bytes,
control DNS responses, supply crafted profiles, and impersonate a server
using an unrelated certificate. Treat an authenticated server's pushes as
untrusted configuration. The embedding application is responsible for
selecting trusted roots, provisioning credentials and protecting its own
process, packet interface, OS routing and DNS settings. Host compromise,
traffic analysis and denial of all network access are outside the core's
guarantees.

## Threats, boundaries and controls

| Threat | Boundary | Required mitigation | Evidence |
|---|---|---|---|
| Rogue server, DNS redirection or wrong-endpoint failover | Resolver, dialer, TLS peer | Verify the chain, validity, server purpose and configured identity before sending secrets. Clone per-endpoint TLS settings and preserve identity across retries. | SEC-001, SEC-009, FR-006, FR-016 |
| Forged resets, ACKs or control records | Transport and TLS stream | Enforce generation/session binding, packet and sequence constraints, protection mode and ACK membership. Accept credentials and pushes only through verified TLS. | FR-004, FR-005, FR-009, FR-010 |
| Forged data, nonce reuse, replays or rekey races | Data-plane key state | Require negotiated AEAD, directional keys, verified tags, bounded receive windows and single replay commit. Stop using a key before limits and serialize generation changes. | FR-011–FR-013, SEC-004 |
| Malicious profiles, files or server pushes | Parser, caller-authorized filesystem and session configuration | Bound lengths and nesting. Read through an explicitly authorized root/resolver. Reject executable directives, unsafe paths, ambiguous protection and security downgrades. | FR-014, FR-023, SEC-003, SEC-005, SEC-006 |
| Floods, blocked I/O or retry storms | Transport, tunnel and scheduler | Bound storage and deadlines. Use cancellable backoff, bounded per-attempt work and explicit resource ownership. | FR-017–FR-020, SEC-005, SEC-010 |
| Sensitive diagnostics and retained credentials | Public API, logs, failures and fixtures | Report typed codes and allow-listed fields. Scope tokens and key material to the session or generation that owns them. | SEC-002, SEC-008 |
| Vulnerable or unlicensed code or generated inputs | Dependencies, tooling and fixtures | Review pinned dependencies, provenance and release inventory. Use maintained crypto implementations. | SEC-007, NFR-008, NFR-009 |

## Identity, profile and failure policy

- Require an explicitly provisioned CA pool or an explicit caller choice of
  system roots. Verify the chain, time and server authentication usage.
  Where the profile requests OpenVPN KU/EKU checks, also enforce those
  constraints on the verified leaf. The DNS name or IP address from the
  configured remote is the default SAN identity. An explicit override
  replaces the expected DNS/IP identity for that endpoint. SNI, where
  applicable, describes the configured server and never follows an untrusted
  resolved address.
- An explicit `verify-x509-name` policy makes the configured exact
  certificate name or subject an authorized identity with full chain and
  server-purpose checks. An explicit `name-prefix` match is an additional
  check alongside the exact DNS/IP identity. Reject empty, ambiguous or
  unrepresentable identity policy. Treat certificate, required control
  protection, authentication and negotiated security failures as terminal.
  Never retry them with weaker options or with different credentials.
- Untrusted profiles can supply inline material only when the embedding
  application accepts the profile as a credential and trust configuration.
  Disable referenced file access unless the caller supplies an authorized
  root or resolver. Accept relative references confined to that root.
  Reject traversal, root escapes including symlinks, absolute/device/UNC
  paths, and non-regular files. Validate and read through the same
  confined handle. If the caller owns resolution, document the same
  confinement and byte-budget contract. [Go filesystem root API](https://pkg.go.dev/os#Root)
- A connected proxy or custom transport can delay or alter packets and must
  honor the cancellation and packet ownership contract. TLS and AEAD
  validation remain in the core. Pushed route/DNS settings, when supported,
  are validated metadata for the embedding application. The core does not
  execute profile or server commands or mutate host settings.
- Retry transport timeouts and I/O loss with bounded per-attempt resources.
  Treat a UDP packet rejected before authentication as an input drop.
  Authentication failure from a verified peer is terminal. The same
  cancellation path stops retry timers, in-flight transport operations,
  control loops and owned resources. Token or password-provider operations
  must honor the attempt context.

## Bounds and cryptographic policy

Use standard Go TLS, X.509, randomness, AES, HMAC and AEAD primitives.
Introduce ChaCha20-Poly1305 only through a reviewed maintained Go module
if required by the chosen toolchain. Use TLS 1.2 and 1.3 under Go's secure
cipher defaults. Control wrappers and AEAD tag/nonce formatting follow the
[protocol baseline](PROTOCOL_BASELINE.md). Disable compression, non-AEAD
data ciphers, replays without verification, SHA-1 certificate signatures
and automatic fallback to legacy key derivation. HMAC-SHA1 for an explicitly
selected or documented default tls-auth digest is distinct from signature
verification and cipher negotiation.

The following limits are initial client policy. Verify them against the
pinned peer before shipping. The encoded wire length and implementation
allocation cap are both enforced independently.

| Resource | Initial bound or rule |
|---|---|
| Transport frame | 16 KiB default receive cap, maximum configurable cap 65,535 bytes, subject to transport limits |
| Profile and references | 1 MiB each for the profile and aggregate referenced material, 64 KiB per line, 64 effective remotes, one connection-block level plus one inline material block |
| Reliable control | 12 retained transmit and 12 receive messages per generation, eight ACK IDs per packet, six UDP retransmissions per message, 16-second retransmit interval cap, and an overall deadline |
| TLS and pushed options | 10-second dial and 60-second control negotiation defaults with explicit finite ceilings on configurable values, 4 KiB per key-method string, 16 KiB aggregate push options and at most 16 push parts |
| Replay | Per-direction and per-generation data state. UDP data window of 64 packet IDs and 15 seconds for reordered IDs. TCP accepts increasing data IDs. Protected outer control uses separate bounded counter/timestamp tracking scoped to the session. |
| Session generations | One active, at most one retiring and at most one pending. A replacement overlap never exceeds either generation's applicable hard key lifetime. |
| AEAD use | Schedule a rekey with headroom before the earlier of the cipher's usage limit and the packet counter limit. For AES-GCM, use an initial per-direction hard ceiling of 2^24 sent packets per key, or a lower documented cipher-specific limit. |
| Data queues and endpoints | Bounded queues, per-attempt timeouts and capped exponential backoff with jitter. Unlimited retry is an explicit caller policy and remains cancellable. |

The usage-triggered rekey samples the two key directions every
250 ms. It retains a 1,024-packet minimum and estimates the additional
reserve from recent peak consumption, the configured admission and
handshake deadline, and 500 ms of scheduling margin. The adaptive
reserve is capped at one quarter of the key limit. For AES-GCM with
a four-second rekey budget, a sustained 100,000 packets per second
in one direction reserves about 450,000 packets. Bursts above the
sampled envelope or delays exceeding the cap may reach the hard limit.
Transmission stops at that limit. Rekey reports identify usage-based
triggers and include the time spent awaiting admission.

An invalid MAC or AEAD tag never moves an acceptance window, updates
liveness, releases plaintext or generates an ACK. Use constant-time
verification. A counter cannot roll over under the same data key. Clear
owned mutable secret buffers where practical, then discard references on
failure, rekey retirement and Close. Go, the TLS stack and the caller
may retain other copies. This process provides best-effort cleanup without
a memory-forensics guarantee.

Use only documented diagnostic fields, such as error code, session stage,
configured endpoint index and bounded aggregate counters. Never include
control messages, raw profile lines, credentials, keys, tokens, crypto
buffers, or tunneled payloads in events and errors. Generated artifacts
and test captures follow the same redaction requirements.
[Provenance and fixture policy](PROVENANCE.md)

## Implementation and release checklist

- [ ] **M2** Demonstrate negative chain, name, expiry, EKU and missing certificate cases, with zero credentials emitted before TLS verification. Verify wrong-key, malformed ACK, replay, loss/reorder and forbidden v2 resend cases. Evidence in FR-005–FR-010 and SEC-001–SEC-004.
- [x] **M3** Independent exporter and packet vectors pass. Replay tests reject forged high IDs. Generation tests verify bounded overlap, expiry and rollover with fresh keys. [Data tests](../internal/data/channel_test.go) · [Live rekey evidence](COMPATIBILITY_MATRIX.md#evidence-records)
- [x] **M4** Tests verify malformed profile diagnostics, unsafe file rejection, limit boundaries, and rejection of compression, insecure verification and unapproved ciphers. [Profile parser tests](../profile/parse_test.go) · [TLS identity tests](../internal/tlscontrol/identity_test.go) · [M4 evidence](MILESTONES.md#m4--profile-parser-and-configuration)
- [x] **M5** Mixed-endpoint tests verify SNI, identity and token isolation. Retry tests cover terminal security failures, cancellation, bounded redacted events and joining workers on shutdown. [Interop tests](../tests/interop/failover_test.go) · [Lifecycle tests](../client/retry_test.go)
- [ ] **M6** Fuzz, race, dependency, license and SBOM checks passed. The independent security review remains a release gate. [Hardening evidence](HARDENING.md)
- [x] **M7** The stock Xray integration exercises TCP and UDP through OpenVPN, reconnect, bounded shutdown and interface-bind failure. [Boundary](adr/0007-xray-linux-egress.md) · [Interop test](../tests/interop/xray_test.go)
