# Independent Technical & Security Audit Plan

**Status: PLANNED - no external audit is represented as completed.**

This document defines the scope, method, evidence requirements and release gates for an independent review of OpenVPN Go. It is a plan, not an audit report, certification, penetration-test result or assurance that the implementation is free of defects.

## 1. Objectives

Obtain reproducible, revision-specific evidence that the project:

- implements its documented OpenVPN client protocol scope correctly;
- uses TLS, key derivation, AEAD, nonce, replay and rekey mechanisms safely;
- handles hostile profiles, network input, server pushes and resource pressure defensively;
- interoperates with pinned reference peers and explicitly authorized external services;
- has measurable performance and lifecycle behavior under representative and adverse conditions;
- has traceable source provenance, dependency licensing and reproducible release artifacts.

The review must identify limitations as well as successful results. A passing test suite or clean scanner result is not proof of security.

## 2. Audit status and immutable target

| Field | Planning value |
|---|---|
| Repository | https://github.com/HamedSanaei/openvpn-go |
| Project | OpenVPN Go |
| Language / toolchain | Go; version pinned in go.mod (Go 1.26.11 at plan authoring) |
| License | MIT, subject to provenance and rights review |
| Protocol role | OpenVPN TLS-mode client; no server implementation in initial scope |
| Planning snapshot | 2026-11-27 |
| Main SHA at plan authoring | 6a1246c63a94679ea5f95f82d5d149f9d5ec6533 |
| Final audit target | To be selected and frozen at external-audit kickoff |

The planning snapshot SHA is recorded for traceability only. It is not automatically the audited revision. Before an auditor starts, record the exact full commit SHA, tag (if any), Go toolchain, dependency graph, build flags, operating systems, architecture and CI run identifiers. Any source change creates a new revision; the auditor must state whether it was reviewed or requires retest.

Do not rewrite or force-push the audited commit. Keep the audit branch or tag immutable for the duration of the engagement.

### 2.1 Existing findings to revalidate

The following issues were open at plan authoring and must be re-tested against the frozen audit SHA. They are review inputs, not automatic conclusions about the current revision. Preserve each issue's original baseline and distinguish a reproduced defect from a historical observation:

- [#49](https://github.com/HamedSanaei/openvpn-go/issues/49): forced client-initiated TCP rekey against Proton VPN was not repeatable in the previously documented runs.
- [#86](https://github.com/HamedSanaei/openvpn-go/issues/86): bounded receive-queue overflow and missing aggregate drop observability.
- [#88](https://github.com/HamedSanaei/openvpn-go/issues/88): DNS capability advertisement versus implemented DNS push metadata.
- [#106](https://github.com/HamedSanaei/openvpn-go/issues/106): native UDP datagram size ceiling versus the effective tunnel MTU.
- [#107](https://github.com/HamedSanaei/openvpn-go/issues/107): cipher availability preflight under Go's FIPS-only runtime policy.

Reproduce each finding on the target revision with its original test conditions where safe and authorized. Record whether it is fixed, still present, not reproducible, version-specific or superseded. Do not infer that a merged pull request closed an issue unless the relevant behavior and regression test are verified.
## 3. Independence and assurance rules

The external reviewer must be independent of the implementation work being reviewed. Before engagement, record:

- reviewer identity, organization, relevant OpenVPN / VPN protocol and Go security experience;
- any prior contribution, employment, financial interest or other conflict involving this repository or its maintainers;
- exact review scope, exclusions, methods, dates and tested commit;
- whether the reviewer performed source review, hands-on testing, cryptographic analysis, interoperability testing or only a subset;
- whether findings were retested by the reviewer after remediation.

A maintainer self-review, automated CI run, AI-assisted review or review by the original author is useful engineering evidence, but it is not an independent external audit.

Do not claim independent audit, certification, formal verification or blanket security until the relevant independent report exists. Never imply FIPS validation or certification from ordinary Go FIPS runtime tests.

## 4. Scope

### 4.1 In scope

Review the complete client implementation and the security-relevant boundaries that ship with or support it:

- Public API and lifecycle: client configuration, Connect, Run, Close, events, statistics, retries and failover.
- Profile handling: OVPN parsing, directive validation, inline material, referenced files, resolver contracts and diagnostic redaction.
- Transport: UDP datagram handling, TCP framing, custom PacketConn contracts, size limits, cancellation and ownership.
- Protocol core: wire parsing, opcode/state validation, control-channel reliability, ACK handling, TLS negotiation, authentication, pushed options and session generations.
- Data plane: key export, cipher negotiation, AEAD protection, nonce construction, packet identifiers, replay windows, fragmentation, MTU handling and rekey.
- Integrations: Linux TUN/Xray adapter, optional userspace netstack module, host-network and proxy adapters, DNS/MSS handling and privilege boundaries.
- CLI and diagnostics: profile inspection, error classification, output redaction and handling of malformed input.
- Build and release chain: GitHub Actions, pinned actions, dependency graph, SPDX inventory, license notices, attestations, archive reproducibility and release approvals.
- Documentation and public compatibility claims: compare every claim to revision-specific test evidence.

### 4.2 Out of scope unless separately agreed

- OpenVPN server implementation, TAP / layer-2 bridging and features explicitly listed as non-goals in README.
- Security of the Go compiler, operating system, hypervisor, external VPN provider or upstream OpenVPN peer itself.
- Security of the embedding application's account provisioning, endpoint selection, route/firewall policy or host compromise, except at documented integration boundaries.
- A formal legal clean-room opinion, legal advice, FIPS validation, Common Criteria certification or a guarantee against all vulnerabilities.
- Testing against third-party accounts or systems without explicit authorization.

The auditor may recommend additional scope when source review reveals a material dependency or trust boundary that cannot be assessed from the current scope.

## 5. Threat model and assets

Use docs/SECURITY_MODEL.md as the authoritative project threat model. The auditor should validate it against the implementation and report missing or inaccurate assumptions rather than silently adopting it.

### 5.1 Assets to protect

- VPN usernames, passwords, access tokens and authentication responses.
- Client private keys, CA trust anchors, TLS session material, exported data keys and nonce / packet-counter state.
- Tunnel plaintext, authenticated packet delivery and peer identity.
- Profile contents, referenced files, DNS and endpoint metadata.
- Availability and bounded ownership of sockets, queues, timers, goroutines, memory and CPU.
- Release credentials, signing identities, build provenance, dependency integrity and project IP / license rights.

### 5.2 Adversary capabilities to consider

Assume an attacker may control or influence the network path; drop, delay, duplicate, reorder, truncate or inject packets; return malicious DNS answers; present an unrelated or invalid certificate; send malformed control, data and push messages; provide crafted profile files; trigger reconnect and rekey timing; and attempt to exhaust bounded resources.

Treat even authenticated server pushes as untrusted configuration. The embedding application remains responsible for protecting its process, operating-system routes, firewall, DNS settings, local tunnel and credential provisioning.

The auditor must distinguish remote unauthenticated, authenticated-peer, local-user and compromised-host attack prerequisites. Do not overstate a denial-of-service or compatibility issue as remote code execution or a cryptographic break without evidence.
## 6. Review workstreams

### A. Protocol and state-machine correctness

Inspect the protocol baseline and compare implementation behavior with the public OpenVPN wire specification, official manuals and pinned reference implementations.

Review at minimum:

- packet headers, opcode and key-ID validation, direction, session ID and generation binding;
- UDP datagram boundaries and TCP length framing, partial reads/writes and malformed lengths;
- initial reset, TLS control handshake, key-method exchange, authentication and push processing;
- reliable control sequencing, ACK membership, retransmission, duplicate suppression and bounded queues;
- tls-auth, tls-crypt and tls-crypt-v2 framing, key direction and cookie paths;
- negotiated DATA_V2 format, peer ID, packet identifiers and authenticated packet delivery;
- fragmentation, reassembly, packet-size limits, MTU / MSS calculations and transport-specific ceilings;
- peer-initiated and client-initiated rekey, key-ID rollover, overlap and retirement;
- failover, retry classification, endpoint-specific identity and terminal security errors;
- DNS capability advertisement, parsing, metadata and the boundary between metadata and actual resolver enforcement.

For every state transition, verify allowed predecessor states, authenticated inputs, timeout/cancellation behavior, duplicate handling and the state changes that must not occur on invalid input.

### B. Cryptography and TLS

A reviewer with applied cryptography experience must inspect:

- certificate-chain validation, server identity / SAN policy, EKU / KU constraints, time validity and SNI behavior;
- TLS version and configuration policy, client authentication, credential ordering and secret disclosure before peer verification;
- TLS exporter labels, context, lengths and independent test vectors for TLS 1.2 and TLS 1.3;
- directional key separation, key derivation, key lifetime and generation binding;
- AEAD algorithm selection, tag verification, nonce construction, packet-counter monotonicity and exhaustion handling;
- replay-window correctness under loss, duplication, reordering and concurrent receive;
- rekey overlap, old-key retirement, simultaneous rekey and failed-handshake rollback;
- constant-time operations where required, randomness sources and error handling;
- secret lifetime, best-effort clearing of owned mutable buffers and realistic limitations of Go memory management.

Do not propose a wire-incompatible primitive substitution, weaken peer verification, silently downgrade ciphers or disable rekey limits as a fix. Any cryptographic concern must cite the exact code path, protocol requirement, threat preconditions and reproducible evidence.

### C. Application and implementation security

Inspect parsers and all untrusted-input boundaries for panic, integer overflow, unsafe conversions, path traversal, symlink escape, malformed PEM / certificates, unbounded allocation, recursion, queue growth, goroutine creation and log injection.

Review context propagation, deadline enforcement, lock ordering, data races, channel closure, blocked I/O, timer ownership, worker shutdown, repeated Close, reconnect storms and resource release on every error path.

Verify that errors, events, CLI output, CI logs and test artifacts do not disclose credentials, private keys, tokens, raw profiles, raw control messages or tunnel payloads.
### D. Integration and platform boundaries

Review the Linux TUN and Xray integration, optional userspace netstack, host networking, DNS, MSS and proxy adapters. Confirm that the protocol core does not unexpectedly mutate host routes or firewall rules, execute profile directives, require unnecessary privileges or import application-specific packages.

Test interface binding, DNS behavior, packet ownership, cancellation, restart, shutdown, MTU edge cases and failure propagation. Document platform-specific limitations instead of generalizing a Linux-only result to all supported systems.

### E. Interoperability

Use the exact peer versions and build digests recorded in docs/COMPATIBILITY_MATRIX.md and docs/PROVENANCE.md. The current documented matrix includes pinned OpenVPN Community 2.6.x / 2.7.x peers, historical AEAD-policy peers, OpenVPN 3 Core, MikroTik RouterOS CHR, OpenVPN Access Server and Xray integration.

Re-run only cases in the agreed scope and record exact combinations of transport, TLS version, authentication, control protection, data cipher, peer build and result. Provider-profile testing is permitted only with profiles and accounts explicitly authorized by their owner. Keep raw exports, credentials, private keys, addresses and raw logs outside Git; publish only redacted summaries.

A successful connection is not enough. Where supported, verify bidirectional packet delivery, reconnect, failover, peer-initiated and client-initiated rekey, DNS behavior, MTU boundaries and clean shutdown. Record unsupported modes as unsupported, not as passing.

### F. Performance and reliability

Measure on a documented, repeatable host and compare against pinned OpenVPN Community and OpenVPN 3 Core builds using the same peer, network namespace, cipher, TLS version, packet size, traffic direction and workload.

Record throughput, latency distribution (including p50 / p95 / p99 where meaningful), CPU time, peak RSS, allocations, heap retention, goroutine count, queue high-water marks, packet loss, reconnect time and behavior during rekey. Include idle, steady-state, burst, slow-consumer, lossy-network and multi-session workloads.

Use multiple samples and report medians / spread. State whether DCO, kernel acceleration, cgo, userspace or host TUN is enabled. Never compare unlike workloads or present a microbenchmark as end-to-end VPN throughput.

### G. Supply chain, provenance and licensing

Independently verify:

- go.mod / go.sum and optional-module dependency graphs, checksums and selected versions;
- known vulnerabilities and whether affected packages are reachable in shipped build targets;
- license identifiers, copyright notices, transitive notices and SPDX SBOM completeness;
- provenance of implementation code, copied snippets, generated files, test fixtures, vectors and build tools;
- pinned GitHub Actions, permissions, secrets exposure, artifact attestations and release workflow protections;
- reproducibility of release archives and correspondence between the reviewed source SHA and published artifacts;
- MIT licensing authority for every material included in the repository.

Read docs/CLEAN_ROOM.md and docs/PROVENANCE.md, including the recorded prior-exposure limitation. The auditor must not convert a spec-driven implementation description into a formal clean-room or legal conclusion. Legal questions about rights or ownership must be referred to qualified counsel.
## 7. Required test and evidence procedure

### 7.1 Start with the repository's existing commands

Run the repository-defined commands on the frozen audit revision and retain complete logs:

~~~sh
go version
go env GOOS GOARCH GOVERSION CGO_ENABLED
gofmt -l .
make test
make race
make vet
make fuzz-smoke
make audit
make bench
~~~

For sustained fuzzing, run the documented campaign and retain target, duration, seed corpus revision, crash corpus and environment:

~~~sh
make fuzz
~~~

The interop target requires an explicitly pinned peer binary:

~~~sh
OPENVPN_INTEROP_BIN=/absolute/path/to/pinned/openvpn make interop
~~~

Also run the CI-equivalent cross-platform builds and tests. The optional userspace module is a separate Go module and must be checked independently from its directory:

~~~sh
cd integrations/netstack
go mod verify
CGO_ENABLED=0 go test -timeout 1m ./...
go test -race -timeout 1m ./...
go vet ./...
~~~

These commands are a starting baseline, not a complete audit. Preserve failures and investigate them; do not hide a failure by weakening a test or silently changing the baseline.

### 7.2 Existing fuzz targets

The current hardening workflow defines these core targets:

- FuzzProfile
- FuzzTCPFrame
- FuzzControlPacket
- FuzzProtectedControl
- FuzzDataPacket
- FuzzControlPush

Review the existing corpus and add targets where the audit identifies uncovered parsers or state boundaries, especially DNS push metadata, ExpressVPN framing, fragmentation / reassembly, certificate and key material parsing, endpoint configuration and integration adapters.

For each target, define input bounds, maximum execution time, expected invariants and regression handling. A fuzz run that did not crash is evidence only for the target, corpus, duration and environment recorded.

### 7.3 Negative and adversarial test matrix

At minimum, include:

- wrong CA, wrong DNS / IP identity, expired and not-yet-valid certificates, invalid EKU and missing peer certificate;
- malformed, truncated, oversized and out-of-state control and data packets;
- invalid tags, replayed packets, stale / forged packet identifiers and key-ID rollover boundaries;
- duplicate, reordered, delayed and dropped control / data packets;
- invalid ACKs, retransmission exhaustion and bounded-queue saturation;
- simultaneous and failed rekey, cancellation during TLS and rekey, old-key retirement and reconnect;
- malformed and oversized profile / push inputs, path escape and symlink cases;
- DNS capability negotiation and policy handling with pinned reference peers;
- UDP / IPv4, UDP / IPv6 and TCP size ceilings, fragmentation and MTU boundary behavior;
- blocked reads / writes, slow consumers, repeated Close, endpoint failover and resource exhaustion;
- redaction of secrets in errors, logs, events, CI artifacts and crash reports.

Each discovered defect must have a deterministic regression test where practical. Keep test credentials and cryptographic material synthetic.

### 7.4 Independent oracles

Do not use the implementation under review as the only oracle for its own correctness. Use public protocol specifications, independent test-vector generators, pinned reference peers, separate TLS / crypto implementations where appropriate and independently authored assertions.

Where behavior differs between OpenVPN versions or providers, record the version-specific contract and evidence. Do not label an implementation defect until the expected behavior is established.
## 8. Finding severity and remediation

Every finding must include:

1. unique ID, title, affected commit and affected component;
2. severity and confidence, with rationale (use CVSS 4.0 only when it meaningfully models the issue);
3. attacker position, prerequisites and affected security property;
4. exact file / symbol / code location and relevant protocol reference;
5. minimal reproduction or test case, observed result and expected result;
6. concrete impact, affected versions and explicit limitations;
7. recommended remediation and regression-test requirement;
8. maintainer disposition, fix commit and independent retest result.

Use Critical / High / Medium / Low / Informational for security findings. Track protocol-conformance, compatibility and performance findings separately where CVSS is inappropriate.

Critical and High findings block beta release until fixed and independently retested. This plan does not create a waiver path; any change to that policy requires a separate release-governance decision and an explicit update to docs/RELEASE.md. Medium findings require a documented fix plan and release decision. Low and Informational findings must remain visible in the report or backlog.

Coordinate disclosure privately for vulnerabilities that are not yet fixed. Do not publish weaponizable reproduction details, provider secrets or sensitive captures in public issues. Publish a redacted advisory or report after a fix and retest, consistent with the project's disclosure policy.

## 9. Required deliverables

The engagement is complete only when the agreed deliverables are received and linked to the exact reviewed revision:

- **Scope and methodology:** auditor, dates, commit SHA, tools, versions, environments, exclusions and limitations.
- **Executive summary:** overall outcome, material risks and release recommendation.
- **Technical report:** protocol, state-machine, parser, transport, lifecycle and integration findings.
- **Cryptographic review:** TLS identity, key derivation, AEAD, nonce, replay and rekey analysis.
- **Interoperability report:** exact peer matrix, test cases, failures and unsupported modes.
- **Performance report:** reproducible workloads, peer versions, raw measurements and methodology.
- **Supply-chain / license report:** dependency, provenance, SPDX and release-pipeline findings.
- **Findings register:** severity, evidence, remediation, disposition and status.
- **Retest report:** exact fix commits and independently verified closure of findings.
- **Signed reviewer statement:** identity, independence declaration, scope, reviewed SHA and explicit statement of what was not examined.

Recommended repository location after the engagement:

~~~text
docs/security/audit/
  README.md
  scope-and-methodology.md
  executive-summary.md
  findings.md
  interoperability.md
  performance.md
  supply-chain-and-license.md
  retest-report.md
  final-report.pdf
~~~

Do not commit private provider profiles, credentials, private keys, raw packet captures, unredacted logs or confidential exploit details. Keep confidential working papers with the auditor under the engagement's agreed retention and disclosure terms.
## 10. Release gates

An audit report does not automatically authorize a release. Before publishing a beta or stable version:

- [ ] The audited source SHA is identified and matches the release candidate.
- [ ] The independent auditor's scope, independence, methodology and limitations are recorded.
- [ ] No unresolved Critical or High security finding remains, unless a documented exception is approved under the release policy.
- [ ] All agreed findings have an owner, disposition and retest status.
- [ ] Security-critical fixes have regression coverage and pass CI on the release candidate.
- [ ] Required protocol and interoperability cases pass on the pinned peers.
- [ ] Fuzz, race, static analysis, vulnerability, license, SBOM and release-reproducibility evidence is current.
- [ ] The license and provenance reviewer independently signs off on the exact candidate.
- [ ] Security and provenance approvals are provided by separate reviewers as required by docs/RELEASE.md.
- [ ] The public report describes the exact revision, scope, dates, findings and limitations; no broader claim is made.

If code changes after the audit, assess their security impact. Changes to TLS, cryptography, protocol state, parser, transport, session lifecycle, integrations or dependencies require targeted review and may require a full or partial retest.

## 11. Suggested execution phases

Time estimates are planning aids only and depend on auditor availability and findings.

| Phase | Work | Indicative effort |
|---|---|---|
| 0. Preparation | Freeze revision, scope, threat model, evidence package and auditor brief | 2-4 working days |
| 1. Internal readiness | Reproduce existing evidence, close known regressions and organize test harnesses | 1-2 weeks |
| 2. External review | Source review, protocol / crypto review, testing and report drafting | Agreed with auditor |
| 3. Remediation | Triage, fix, regression tests and maintainer review | Finding-dependent |
| 4. Independent retest | Verify fixes against exact commits and update the report | Agreed with auditor |
| 5. Release approval | Security and provenance sign-off, report publication and candidate verification | 1-3 working days |

## 12. Engagement acceptance checklist

- [ ] Auditor selected using relevant Go, TLS / cryptography and VPN protocol experience.
- [ ] Independence and conflict-of-interest statement received.
- [ ] Scope, exclusions, confidentiality and disclosure terms agreed.
- [ ] Exact target SHA and toolchain frozen.
- [ ] Existing docs/SECURITY_MODEL.md, docs/TEST_STRATEGY.md, docs/HARDENING.md, docs/COMPATIBILITY_MATRIX.md, docs/PROTOCOL_BASELINE.md, docs/EXTERNAL_INTEROP.md, docs/PROVENANCE.md, docs/CLEAN_ROOM.md and docs/RELEASE.md supplied.
- [ ] Existing issues and prior audit evidence supplied with their original commit context.
- [ ] Test lab is isolated and uses synthetic credentials or explicitly authorized external profiles.
- [ ] Report format, severity model, remediation window and retest budget agreed.
- [ ] Public / confidential deliverables and publication date agreed.

## 13. Existing project references

- [Security model](SECURITY_MODEL.md)
- [Test strategy and acceptance requirements](TEST_STRATEGY.md)
- [Hardening evidence](HARDENING.md)
- [Compatibility matrix](COMPATIBILITY_MATRIX.md)
- [Protocol baseline](PROTOCOL_BASELINE.md)
- [External interoperability evidence](EXTERNAL_INTEROP.md)
- [Architecture](ARCHITECTURE.md)
- [Provenance ledger](PROVENANCE.md)
- [Clean-room and source-separation limitations](CLEAN_ROOM.md)
- [Beta release policy](RELEASE.md)
- [Open findings and project backlog](https://github.com/HamedSanaei/openvpn-go/issues)

---

**Current disposition:** this plan is ready to guide preparation and an external engagement. It does not mean an independent audit has started, that an auditor has been appointed, that the project has passed an external review, or that any certification has been obtained.
