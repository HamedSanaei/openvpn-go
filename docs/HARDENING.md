# M6 hardening evidence

The automated checks use the Go version in `go.mod`. The hardening workflow
preserves interoperability, fuzz, race, vulnerability and benchmark results.
[Continuous integration](../.github/workflows/ci.yml) · [Hardening workflow](../.github/workflows/hardening.yml)

| Platform | Observed result |
|---|---|
| Linux amd64, Ubuntu 26.04 LTS under WSL | cgo-free build and tests, race detector, vet and both OpenVPN peer suites passed. |
| Linux arm64 | cgo-free build and tests passed using QEMU user-mode 10.2.1 on the Linux amd64 host. Native execution is configured in CI. |
| Windows amd64 | The cgo-free build and tests, race detector and vet passed locally. The hosted matrix uses Windows Server 2025. |
| macOS arm64 | The binary and test packages cross-compiled on Linux. The native test job uses the hosted macOS 15 runner. |

## Fuzz and shutdown coverage

Each target ran for one minute on Linux amd64. All completed without a
failing input. The test for repeated reconnect exercises 25 authenticated
fake forwarding generations, closes each transport once and joins both
workers before reuse. Linux race tests also run the lifecycle, transport
and session packages 20 times.

| Target | Inputs exercised |
|---|---:|
| Profile | 1,169,902 |
| TCP framing | 2,383,957 |
| Control packet parsing | 4,312,858 |
| Protected control | 2,619,998 |
| Data and replay | 2,965,615 |
| TLS push | 1,248,436 |

[Fuzz commands](../tests/fuzz/README.md) · [Lifecycle regression](../client/retry_test.go)

## Performance budgets

Run `make bench` and pass its output to `python3 tools/check_benchmarks.py`.
The checker uses medians from three samples on Linux amd64. Packet
throughput measures a 1,400-byte seal and open pair. Idle heap estimates
retained bytes per undialed client across a 256-client batch with configured
TLS and two endpoints. The reconnect benchmark measures a virtual packet
transport loss through delivery of the first forwarded probe after recovery,
including the configured jitter and scheduling. It excludes a real TLS
handshake and network latency.

| Measurement | Median limits |
|---|---|
| Data seal/open, per cipher | 10 µs per packet, 3,300 B/op, 4 allocs/op |
| Discard unauthenticated data | 8 µs, 1,650 B/op, 2 allocs/op |
| Idle client creation | 150 µs, 24,576 B/op, 185 allocs/op, 16 KiB retained per client |
| Reconnect and forward | 5 ms, 4,096 B/op, 55 allocs/op |

On the Intel Core i5-13450HX test host, the 1,400-byte round trip took
about 1.1 µs for AES-128-GCM, 1.2 µs for AES-256-GCM and 1.9 µs for
ChaCha20-Poly1305. It used 3,104 B and four allocations on all three
ciphers. The rejected packet used 1,552 B and two allocations. An idle
client retained approximately 12 KiB. Reconnect measured 1.14 ms and
2,822 B/op. Reusing and clearing the two forwarding buffers reduced
reconnect allocation from 35,576 B/op in the initial benchmark.
[Packet benchmarks](../internal/data/benchmark_test.go) · [Client benchmarks](../client/benchmark_test.go) · [Budget checker](../tools/check_benchmarks.py)

## Supply chain and review

`make audit` verifies Go module checksums, compares used modules on the
four targets to the reviewed inventory, checks the SHA-256 of shipped
license notices and runs Govulncheck. Govulncheck 1.10.0 reported no known
vulnerabilities in the scanned Linux amd64 build on 2026-11-26. The SPDX
inventory covers the project, Go standard library and linked modules.
The generated file also passed validation against the SPDX 2.3 JSON
schema.
Go module-selection entries without compiled packages are recorded
separately in the audit manifest.
[SPDX inventory](sbom.spdx.json) · [Audit manifest](../tools/release-audit.json) · [Go vulnerability scanning](https://go.dev/doc/security/vuln/)

The implementation review found that `ping-exit` shared the reconnect
path with `ping-restart`. The fix preserves the peer's terminal shutdown
request and rejects a push that requests both policies. A live test covers
the terminal result on both pinned peers. The separate reviewer sign-off
is pending. The reviewer should inspect TLS authentication and the handling
of failed control negotiation, replay and rekey state, path confinement,
adapters and credential lifetime, and attach findings or approval to the
release revision.
[Liveness test](../internal/session/session_test.go) · [Interop tests](../tests/interop/hardening_test.go) · [Security policy](SECURITY_MODEL.md)
