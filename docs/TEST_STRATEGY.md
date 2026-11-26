# Test and validation strategy

M0 records testable acceptance criteria. Each listed gate requires passing
evidence by the indicated milestone. The [milestone register](MILESTONES.md)
links completed evidence. The [engineering task register](TASKS.md) maps the
work to these requirements.

## Functional acceptance

| Requirement | Gate | Planned test and pass condition |
|---|---|---|
| FR-001 | M2, M6 | Interop with OV26-TLS using a verified TLS client session and accepted push. Once M4 is available, reject server and static-key profiles before dialing. |
| FR-002 | M1, M6 | Send back-to-back loopback UDP datagrams and assert exact packet boundaries. Drop zero-size and truncated datagrams. Pass the UDP interop cases. |
| FR-003 | M1, M6 | Decode split prefixes/bodies and coalesced frames under short reads and writes. Reject zero, oversize and incomplete frames without oversized allocation. Pass the TCP interop cases. |
| FR-004 | M2 | Decode known opcode/key-ID fixtures across all three key bits. Route control and data to their handlers. Reject invalid opcodes, wrong-direction resets and truncated headers without changing state. |
| FR-005 | M2 | Over the reliable TLS stream, complete reset, TLS, key method 2 and push with the pinned peer. Exercise single and continued pushes and reject malformed or out-of-state control messages. Assert no data path before verified configuration. |
| FR-006 | M2, M4 | Establish TLS using DNS SAN, explicit IP SAN, explicit DNS/IP override and authorized exact X.509 name/subject policies. Verify name-prefix policy against both the SAN and the prefix. Fail every mismatch and invalid chain. |
| FR-007 | M2 | Connect using a generated CA, client cert and matching key. A mismatched key fails locally, and absent or untrusted client certificates fail authentication. |
| FR-008 | M2, M4 | With a generated client certificate and test credentials, connect using configured credentials, fail a wrong password with a redacted terminal error, and prove credentials are absent after failed server verification. Cover caller-provided and parsed credentials. |
| FR-009 | M2, M3, M6 | Connect using OV26-TA, OV26-TC, OV26-V2 and OV26-V2C. Validate exact protection vectors, cookie and non-cookie reset paths, mismatched mode/key/digest/direction, malformed wrapped lengths and rejected post-handshake resend requests. |
| FR-010 | M2 | Inject loss, reordering and duplicates around the reliable window. Assert retransmissions keep the reliable ID and use a fresh protected wrapper ID. Reassemble TLS bytes exactly once and in order. Reject wrong-session and unsent ACKs while keeping retries bounded. |
| FR-011 | M3, M6 | Force each allow-listed AEAD in the pinned peer and assert the chosen cipher and bidirectional IP payload equality. A missing, legacy, unexpected or non-overlapping cipher is a terminal negotiation error. |
| FR-012 | M3 | Compare independent DATA_V2 vectors for all three AEADs. Flip peer ID, explicit counter, tag and ciphertext, test stale/zero and duplicate IDs, and inject a forged high ID. Observe zero plaintext delivery for invalid packets and successful subsequent valid reception. |
| FR-013 | M3 | Compare exported bytes from a controlled TLS fixture against an independent TLS backend for TLS 1.2 and 1.3. Rotate from initial ID through 7 to 1, with peer- and client-initiated rekey, expired old-key rejection, and no sends at the key-use ceiling. |
| FR-014 | M4 | Load generated CA, certificate, key and auth material inline, via a confined resolver and via caller-supplied credentials where applicable. Compare effective configuration and reject malformed or inaccessible material with redacted diagnostics. |
| FR-015 | M4, M5 | Parse top-level remotes with final defaults and connection blocks with positional inheritance. Assert effective protocol, address family and port, declared order, rejection of mixed forms, and deterministic shuffling that retains all candidates. |
| FR-016 | M5 | Fail a UDP transport and connect to a TCP endpoint with a different expected identity. Capture each dial choice and observed SNI. Wrong names or CAs are terminal and never relax identity on a later attempt. |
| FR-017 | M1, M5 | Block fake dial, handshake, read and write operations. Trigger deadline, cancellation, and repeated concurrent Close. Assert bounded completion and a single release of owned resources. |
| FR-018 | M5 | Use fake time and entropy to verify exponential delays, jitter bounds, finite exhaustion, successful reset of retry state and cancellation under explicit unlimited retries. Identity and auth failures consume no additional attempts. |
| FR-019 | M1, M5 | Connect through a caller-provided fake transport without using the default network dialer. Verify packet boundaries, failure propagation, cancellation and ownership on partial failure/retry. |
| FR-020 | M1, M3 | Compile an external consumer of the public packet API. Exchange complete IP packets through a fake tunnel. Verify size limits, backpressure, ownership and Close behavior. |
| FR-021 | M5 | Observe connection, retry and shutdown using the public state and stats. Verify active endpoint accuracy, concurrent snapshots and absence of secrets and arbitrary-cardinality fields. |
| FR-022 | M7 | Against the pinned target integration revision, pass traffic through the adapter and test reconnect, cancellation and shutdown. Verify the adapter imports only the public core API. |
| FR-023 | M4 | Table-test every registry directive with valid values and malformed variants. Unknown or unsupported security options fail before dialing. Unsupported benign options report a stable code and location without echoing sensitive values. |

## Security acceptance

| Requirement | Gate | Planned test or manual pass condition |
|---|---|---|
| SEC-001 | M2, M4 | Reject wrong CA, hostname, expired or not-yet-valid certificate, absent peer certificate, wrong EKU and missing/malformed identity policy. No credential exchange occurs on these connections. |
| SEC-002 | M2, M5 | Insert unique markers into secret material, auth messages and tunnel traffic, then exercise failure and retry paths. Assert markers and raw peer/profile values are absent from captured errors and diagnostics. |
| SEC-003 | M1, M2, M4, M6 | Boundary-test and fuzz malformed and truncated profile, frame, control and data inputs. Assert no panic, hang, unbounded allocation or partial state commit. Run focused regression inputs from each corpus. |
| SEC-004 | M2, M3 | Property-test control and data replay windows with in-window reordered packets, stale values, duplicates, forged high IDs, rollover and multiple key generations. Invalid packets neither advance state nor deliver data. |
| SEC-005 | M1, M2, M4, M5, M6 | Drive frames, queues, handshake, profile and retry limits to their configured boundary and one past it. Verify bounded allocation, queue lengths and elapsed work under stalled or flooding peers. |
| SEC-006 | M3, M4 | Reject compression, disabled verification, unsupported protection and legacy/non-AEAD settings in profiles and pushes. Confirm zero application data after negotiation failure. |
| SEC-007 | M3, M6 | Maintainer reviews protocol crypto and dependency inventory. Pass only when each primitive resolves to an approved maintained package and each dependency passes provenance and vulnerability review. |
| SEC-008 | M3, M5 | Maintainer reviews owned secret lifetimes through failed handshake, rekey, token replacement and Close. Tests verify retired references and mutable owned test buffers are cleared where possible. Record Go-runtime limitations. |
| SEC-009 | M5 | In mixed UDP/TCP failover, use the same IP under distinct logical identities. Reject cross-endpoint certificates and verify tokens and TLS state are never reused across endpoints. |
| SEC-010 | M1, M5, M6 | Race blocked reads/writes, retry timers and rekey against cancellation and Close. Assert the transport, tunnel resources owned by the session, timers and goroutines settle within the test deadline. |

## Non-functional acceptance

| Requirement | Gate | Planned test or manual pass condition |
|---|---|---|
| NFR-001 | M1, M7 | Build a consumer against the versioned public API and review supported exports. Imports of the internal packages from a consumer fail. |
| NFR-002 | M1, M6 | Build the core with `CGO_ENABLED=0` and run its tests. Check the release dependency inventory for native TLS or cgo requirements. |
| NFR-003 | M6 | Record Linux amd64/arm64 build and test results and Windows/macOS build and test results where supported. |
| NFR-004 | M1, M7 | Run the engine with a fake packet source and no OS network-admin privileges. Code review confirms all privileged host network operations live outside the core. |
| NFR-005 | M6 | Retain benchmark results for throughput, allocations per packet, idle memory and reconnect latency. Measure bounded allocations under adversarial load and record regression thresholds. |
| NFR-006 | M1, M5, M6 | Run the race detector on reconnect, packet processing, rekey and repeated Close tests, with zero reports. |
| NFR-007 | M4 | Compare registry entries to directive docs and parameterized parser tests. Every supported directive appears in both. |
| NFR-008 | M6 | Compare module, tooling and fixture inventory to the provenance ledger. All external versions, notices, scopes and review decisions are recorded. |
| NFR-009 | M1, M6 | Verify formatting, unit tests, race and vet on pull requests. Retain release fuzz, vulnerability and license/SBOM evidence. |
| NFR-010 | M6, M7 | Reconcile all published claims against observed server version, transport, TLS/authentication, cipher and packet format records. Claim only cases with reproducible passing evidence. |

## Execution and evidence

- M1 supplies a deterministic packet transport and manual clock. Use
  generated test roots, credentials and isolated loopback or documentation
  addresses. Store reproduction instructions and provenance for fixtures.
  [Provenance ledger](PROVENANCE.md)
- M2 adds the disposable peer harness and tests control-plane handshakes
  with generated identities. M3 tests authenticated data, independent
  vectors and rekey. Run each required transport and protection mode and
  capture the observed negotiated settings. [Compatibility matrix](COMPATIBILITY_MATRIX.md)
- Make lint and Go checks reproducible with the version in `go.mod`.
  Pull-request CI runs formatting, `go test ./...`, `go test -race ./...`
  and `go vet ./...`. Release validation also includes static analysis,
  fuzz smoke and sustained campaigns, vulnerability checks, a license
  inventory, an SPDX SBOM and performance evidence.
- Retain interoperability records with exact peer version/build and digest,
  OS/architecture, TLS backend/version, negotiated cipher and data format,
  port, transport, identity policy, authentication, fixture revision and
  result. Use synthetic credentials and redacted output. Keep any permitted
  captures in controlled test storage with a safe reference.
- M6 sets measured performance budgets once benchmarks exist. M7 verifies
  adapter traffic flow and lifecycles against its pinned integration
  revision. [Delivery gates](MILESTONES.md)
