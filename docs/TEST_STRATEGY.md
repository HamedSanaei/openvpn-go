# Test and validation strategy

## Test pyramid

### Unit tests
- Packet header/opcode/key-id parsing.
- UDP packet boundaries and TCP length framing.
- Control packet codec, ACK aggregation and retransmit state.
- Replay windows and packet-ID boundaries.
- TLS identity policy and endpoint-specific configuration.
- Key derivation and AEAD packet construction using independently generated vectors.
- OVPN profile parsing, inline blocks, inheritance and diagnostics.
- Endpoint ordering, failover and backoff.
- Lifecycle, cancellation, Close and goroutine ownership.

### Property and fuzz tests
- Fuzz all parsers that consume profile or network-controlled bytes.
- Fuzz TCP frame decoder with truncation, zero length, maximum length and random input.
- Fuzz opcode and control/data packet decoders.
- Property-test replay windows, sequence rollover and ACK bookkeeping.
- Test parser round-trips only where serialization is explicitly supported.
- Every fuzz target must have bounded memory and execution behavior.

### Integration tests
- Run against pinned official OpenVPN server versions in disposable containers or VMs.
- Test UDP and TCP separately.
- Test certificate-only and username/password authentication.
- Test tls-auth, tls-crypt and tls-crypt-v2 independently.
- Test multiple remotes with mixed UDP/TCP and endpoint-specific TLS names.
- Test server restart, packet loss, delayed ACKs, reconnect and rekey.
- Capture protocol traces only with generated test credentials and sanitized fixtures.

### Application integration
- Build a small adapter spike against the target 3x-ui/Xray revision.
- Validate packet flow, cancellation, resource ownership and shutdown.
- Test adapter behavior without importing 3x-ui dependencies into core packages.

## CI checks

Required on every pull request:
- gofmt check.
- go test ./...
- go test -race ./...
- go vet ./...

Required before beta/release:
- static analysis (golangci-lint or agreed equivalent).
- fuzz smoke run and scheduled longer fuzz campaigns.
- govulncheck or equivalent dependency vulnerability scan.
- dependency license inventory / SBOM.
- Linux amd64 and arm64 build/test.
- Windows and macOS compile/test where supported.
- benchmarks for packet throughput, allocations, reconnect latency and idle memory.
- interoperability matrix with exact server versions and configuration fixtures.

## Interoperability evidence

Each test record must include:
- OpenVPN server version and build.
- Operating system and architecture.
- Transport and port.
- TLS mode and certificate identity configuration.
- Authentication mode.
- Data cipher and TLS version negotiated.
- Relevant profile directives.
- Result, logs with secrets redacted, and packet trace reference if safe.

## Performance budgets

Do not invent a hard throughput target before a baseline exists. M1 establishes a reproducible benchmark harness. M6 sets measured budgets for allocations/packet, CPU per Gbit/s, idle goroutines and reconnect behavior.

## Test fixture rules

- Generate CA, server and client certificates specifically for tests.
- Use non-routable example addresses and fake credentials.
- Never commit production .ovpn profiles, private keys or user traffic.
- Record provenance for every fixture in docs/PROVENANCE.md.
