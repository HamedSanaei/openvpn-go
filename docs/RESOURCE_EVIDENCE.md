# Protocol stress and resource evidence

## Bounded loss and rekey soak

`TestLossySessionSoak` sends distinct authenticated traffic for
simultaneous clients through a seeded, two-direction loopback UDP
simulator. Each direction has a 32-packet bound. Seeded loss, duplication
and small scheduled delays produce out-of-order delivery. Seeds
reproduce decisions for the same arrival order. Linux scheduling and
control retransmission timing can change that order. The test checks
completion through repeated rekeys, correct payload and sequence,
replay rejection, queue peaks and the post-soak Go heap. Logs record
per-session seeds, losses, duplicates, reordering, elapsed time, heap
and goroutine count. The nightly workflow runs four clients and 400
echoes per client for each of three seeds. It requires progress in
every rekey phase and 70 percent total delivery. The short interop
run uses 96 echoes and requires two completed rekeys and 50 percent
delivery. The rekeys occupy a larger share of its observation time.
[Soak workflow](../.github/workflows/lossy-soak.yml) · [OpenVPN 3 Core stress reference](https://github.com/OpenVPN/openvpn3/blob/ff9dd3cdb9b993002d46bd3152ecc153b5cc03bd/test/unittests/README-proto-tests.md)

A race-enabled 2.6.23 run in Linux/amd64 verified all three long
scenarios. Measurements include the four simultaneous clients per seed.

| Seed | Verified echoes / sent | Largest queue | Elapsed | Post-soak heap | Post-soak goroutines |
|---:|---:|---:|---:|---:|---:|
| 34 | 1,501 / 1,600 | 5 | 10.29 s | 624,408 B | 5 |
| 2131 | 1,485 / 1,600 | 4 | 12.22 s | 629,880 B | 5 |
| 59341 | 1,493 / 1,600 | 4 | 11.76 s | 631,600 B | 5 |

## Same-peer comparison

Run `TestComparativeBenchmark` in the isolated Linux namespace
described in the interop instructions. Set `OPENVPN_GO_BENCH_BIN`
to a build of `cmd/ovpn-xray`, `OPENVPN_INTEROP_BIN` to the pinned
Community executable, and `OPENVPN3_INTEROP_BIN` and
`OPENVPN3_INTEROP_SHA256` to the pinned Core CLI and digest. The
test runs the three userspace clients sequentially against fresh
instances of the same Community 2.6.23 server. Each runs 4,096
1200-byte encrypted UDP echoes over TLS 1.2 and AES-256-GCM and then
reattaches following a controlled server replacement. Throughput is
successful echo payload bits per second in one direction. CPU time is
the client's Linux process ticks during the measured echo workload.
Peak RSS is the child process high-water mark including startup and
reconnection. Reconnect time starts at server replacement and ends at
the first verified response. The Go standalone microbenchmarks measure
and gate allocations using the existing median budgets.
Three local Go microbenchmark runs passed those budgets. Median
AES-256-GCM data round trips used 3,104 B and 4 allocations.
Reconnect used 2,966 B and 47 allocations. The retained heap was
12,533 B per undialed client.

Observed in an isolated Linux/amd64 WSL2 namespace with Go 1.26.11.
This short single sample includes Linux scheduling, measurement
resolution and adapter overhead.

| Client | Path | Payload Mbit/s | CPU seconds | Peak RSS MiB | Lost echoes | Reconnect ms |
|---|---|---:|---:|---:|---:|---:|
| OpenVPN Community 2.6.23 | Userspace | 656.9 | 0.03 | 10.39 | 0 / 4,096 | 4,973 |
| OpenVPN 3 Core 3.11.8 | Userspace | 696.1 | 0.03 | 13.40 | 0 / 4,096 | 6,172 |
| OpenVPN Go | Userspace via Linux TUN | 569.5 | 0.09 | 13.57 | 0 / 4,096 | 4,300 |

The benchmark requires at least 98 percent delivery in the quiet local
workload and gates Go on 96 MiB peak RSS and a 20-second reconnect
ceiling. It keeps throughput and CPU as observations because this short
sample varies with the host. Kernels with a working DCO device need
separate measurements and must report the driver and backend used.
[Benchmark harness](../tests/interop/comparative_bench_test.go) · [Go microbenchmark budgets](../tools/check_benchmarks.py) · [DCO decision](adr/0008-linux-data-offload.md)
