# Native load and lifecycle evidence

Run from a clean Linux checkout on a dedicated lab host. The test starts
a signed Community peer with generated certificates and sends synthetic
packets over a loopback-only Linux network namespace. It also creates a
PID namespace so an interrupted run removes the peer and its routes.
The wrapper needs passwordless `sudo` for its isolated local run, Python
3, `iproute2`, a TUN device, and the Go version in `go.mod`. Place output
outside the checkout. Build each external reference using the signed
peer instructions. [Reference builds](../tests/interop/README.md)

~~~sh
bash tests/interop/native-load.sh "$PEER" "$PRIVATE_OUTPUT"
~~~

The defaults are UDP, one tunnel, three 3-second windows, one second of
warmup, and mixed 64/256/1400-byte IPv4 packets with a four-packet
request window. Set `OPENVPN_LOAD_NETWORK` to `tcp` or `udp`,
`OPENVPN_LOAD_PACKETS` to `64`, `256`, `1400` or `mixed`, and
`OPENVPN_LOAD_SESSIONS` to the required count up to 1,000. The 1,000 limit
is a lab input bound. Test the workload at higher counts only on
capacity-qualified infrastructure. Keep CPU affinity and frequency
policy, peer hash, tunnel count, packet sizes, window width, warmup and
sample duration fixed between runs. Record NIC and offload settings for
any separate physical-network experiment.

`metrics.jsonl` records delivered payload, successful echo RTT percentiles,
silent and failed tunnels, queues, recent rekeys, connection counts, and
driver-process CPU, heap, stack, RSS, GC, goroutines and open descriptors.
It also records UDP kernel errors and recovery intervals. The companion
`metrics.jsonl.cleanup.json` records resources before setup and after joins.
RTT percentiles are upper bounds from fixed histogram buckets. CPU
includes the Go client, echo and load generator in the driver process.
The Community peer runs in a separate process. Use separate profiles and
NIC counters when attributing saturation. These loopback measurements do
not qualify physical capacity or the optional adapters.

Use `OPENVPN_LOAD_PROFILE=1` for short CPU, heap, mutex and block profile
runs. For baseline comparisons set `OPENVPN_LOAD_HARNESS` to the same
absolute test source in both checkouts. The gate uses unprofiled clean
checkouts on the same controlled runner and verifies environment and
workload metadata, finite complete samples, variance, median goodput,
CPU per Gbit, p99 and an operator-supplied loss ceiling. The optional
workflow requires a dedicated `openvpn-native` runner. Regular CI checks
allocation counts in `TestReusableDataAllocationBudget`.
[Native workflow](../.github/workflows/native-load.yml) · [Comparison tool](../tools/check_native_load.py)

## Soak protocol

First run a short bounded check with `OPENVPN_LOAD_REKEY=2`,
`OPENVPN_LOAD_WINDOWS=3`, and `OPENVPN_LOAD_RESTART_EVERY=2`. The test
stops the local peer for five seconds and records time from restart to
first validated response per tunnel. Use 360-second windows and 240 or
720 samples for an uninterrupted 24-hour or 72-hour run, respectively.
Use `OPENVPN_LOAD_PAUSE_US` to pace request windows during a calibrated
workload. Establish throughput, p99, loss, per-tunnel recovery and RSS/descriptor ceilings for
the hardware and workload before drawing an acceptance decision. Compare
similar windows after warmup and after restart. Retain the raw sanitized
time series and verify cleanup before rerunning.

The seeded loss and reorder suite exercises a separate workload. Seed 29
on `923f51e` lost the final ACK for the first rekey. The client closed
that control lane before it could acknowledge the retransmission, and the
peer rejected the next key ID while the first exchange was incomplete.
The fix lets the previous UDP lane send ACKs during a locally initiated
rekey until the new peer reset is accepted. A controlled packet-loss test
failed on the 2.6.23 baseline and passed on the candidate with Community
2.6.22, 2.6.23 and 2.7.9.

Repeated seed 29 runs also exposed a separate timing-sensitive outcome
during the next key's TLS exchange. The candidate passed one traced run
and two out of five untraced runs. A seed selects relay randomness for
the actual arrival order, which can differ between runs. Existing
deadlines and test assertions still apply. Production SLO evaluation and
the 72-hour soak remain pending.

## Workstation measurements

On WSL2 Linux amd64 `6.18.33.2-microsoft-standard-WSL2`, Intel Core
i5-13450HX, Go 1.26.11, baseline main `923f51e`, three microbenchmark
samples gave these medians. These are local development measurements.

| Workload | Baseline allocations / bytes per operation | Candidate allocations / bytes per operation |
|---|---:|---:|
| 1,400-byte AES-256-GCM seal/open pair | 4 / 3,104 | 0 / 0 with caller-owned buffers |
| Invalid AES-256-GCM frame, copying API | 2 / 1,552 | 1 / 1,536 |
| Cancellable native UDP echo, 1,400 bytes | 12 / 689 | 6 / 305 |
| Cancellable native TCP echo, 1,400 bytes | 13 / 690 | 7 / 306 |

The owned data path retains one ciphertext copy at the queue boundary.
It decrypts into that frame's storage and clears discarded or consumed
plaintext. Fragmentation still uses bounded reassembly storage. Socket
operations reuse direction-local deadline synchronization and retain the
per-call cancellation hook and session write deadline.

Native 1,400-byte socket echoes sampled one round trip in 17. Median
p99 across the three runs was 21.32 to 18.12 µs on TCP and 14.47 to
14.35 µs on UDP. Both directions retain independent cancellation and
restore their deadline before reusing the socket. The owned invalid-tag
and replay benchmarks recorded zero allocations for the 1,400-byte
AES-256-GCM cases. Load reports also include allocation counts and
allocated bytes during each complete measurement window.

With signed Community 2.6.23, three profiled two-second UDP mixed windows
per run measured 216.74 → 225.49 Mbit/s at one tunnel and 599.67 → 611.13
Mbit/s at 16 tunnels. Approximate p99 improved from 0.331 to 0.264 ms and
from 1.576 to 1.261 ms. At 16 tunnels sampled mutex delay attributed to
`Session.write` fell from roughly 0.12 s to 0.05 s, accounting for 2.90%
and 1.47% of the respective mutex profiles. The sample does not justify
splitting generation ownership, so key installation and replay state
continue to share the existing synchronization. Wider simultaneous
TCP/UDP comparison and dedicated runner calibration remain pending.

The virtual workstation exposed no DCO generic-netlink family and had no
native Ethernet target for the 1/10 GbE comparison. [DCO evaluation](adr/0008-linux-data-offload.md)

In the Linux amd64 socket prototype, `sendmmsg` and `recvmmsg` at 1,400
bytes used 2.0 calls per packet for batches of one and 0.0625 for batches
of 32. The respective median payload rates were about 309 and 725 MB/s
across three loopback samples. Copy and scatter/gather TCP framing both
used zero allocations. Their 1,400-byte medians were 6.40 and 6.17 µs
per echo. These tests evaluate the primitive I/O mechanisms. Fairness,
tail latency, cancellation, rekey under saturated traffic and the cost of
batch management in the tunnel remain qualification gates for adoption.

## Dedicated lab comparison

The authorized lab is a KVM guest with one AMD EPYC-Genoa vCPU, about
2 GiB RAM, Linux `7.0.0-44-generic`, Go 1.26.11 and signed Community
2.6.23. The runner used isolated userspace networking, `GOMAXPROCS=1`,
and lower scheduling priority. The data use three 3-second mixed
packet windows at 64 simultaneous active tunnels.

| Transport | Payload goodput baseline → candidate | p99 baseline → candidate | Loss baseline → candidate | Driver CPU s/Gbit baseline → candidate |
|---|---:|---:|---:|---:|
| UDP | 128.50 → 125.37 Mbit/s | 16.20 → 18.28 ms | 2.08% → 1.88% | 4.311 → 4.265 |
| TCP | 101.85 → 110.72 Mbit/s | 18.28 → 19.43 ms | 2.24% → 1.76% | 5.751 → 5.265 |

All tunnels exchanged validated traffic. The host and workload have no
calibrated performance budget. The observed loss and p99 changes leave
larger capacity targets, sustained comparisons and release gating open.

The paced eight-tunnel UDP check returned all 44,954 echoes over three
windows. It recorded 16 total connections, 32 recent successful rekeys
and a recovery p99 of about 579 ms after restarting the local peer.
Goroutines returned to two after cleanup. File descriptor snapshots were
four before setup and six after cleanup, so longer observation is needed
before drawing conclusions about descriptor stability.

The host then ran the same mixed workload with normal process priority,
default Go scheduler settings and no request pacing. Table entries are
baseline → candidate across three 3-second windows. RSS and silent
tunnels are the highest readings in the candidate windows.

| Transport | Tunnels | Goodput (Mbit/s) | p99 (ms) | Loss | RSS (MiB) | Silent tunnels |
|---|---:|---:|---:|---:|---:|---:|
| UDP | 64 | 115.78 → 125.22 | 17.21 → 18.28 | 2.29% → 1.93% | 36.5 | 0 |
| UDP | 128 | 119.61 → 126.67 | 31.55 → 35.62 | 6.57% → 5.31% | 61.5 | 0 |
| UDP | 256 | 113.10 → 130.14 | 48.23 → 45.39 | 14.71% → 12.69% | 115.8 | 0 |
| UDP | 512 | 98.02 → 107.28 | 65.31 → 54.45 | 31.34% → 29.14% | 220.5 | 24 |
| UDP | 1,000 | 72.06 → 73.98 | 135.18 → 106.07 | 55.83% → 55.14% | 414.3 | 150 |
| TCP | 64 | 109.29 → 120.05 | 19.43 → 15.24 | 2.03% → 1.76% | 33.9 | 0 |
| TCP | 128 | 107.23 → 105.71 | 26.31 → 37.85 | 6.04% → 4.97% | 56.2 | 0 |
| TCP | 256 | 93.36 → 91.33 | 78.34 → 83.23 | 14.69% → 12.51% | 104.4 | 0 |
| TCP | 512 | 72.31 → 83.85 | 99.83 → 78.34 | 34.59% → 34.35% | 197.4 | 159 |
| TCP | 1,000 | 57.28 → 71.20 | 162.15 → 112.70 | 59.51% → 54.74% | 363.5 | 193 |

All 1,000 tunnels established. At 512 and 1,000, some tunnels recorded
no validated response in at least one window. At 256, loss exceeded 12%
despite every tunnel returning data. These results bound observed load on
the one-vCPU lab and leave production capacity unqualified. Capacity
planning also needs long-duration measurements under the intended
application workload and an explicit loss and tail latency budget.

The allocation-instrumented run used code at `a463411`, the `923f51e`
baseline and the same test source for both. It covered 64-, 256- and
1,400-byte packets and a mixed workload over both transports with
64 tunnels. Each case ran three two-second windows at full priority.

| Mixed workload | Driver allocations per validated echo | Allocated bytes per validated echo | p99 (ms) |
|---|---:|---:|---:|
| UDP | 29.68 → 19.52 | 5,807.9 → 3,643.6 | 16.196 → 17.208 |
| TCP | 30.75 → 20.48 | 5,817.1 → 3,634.0 | 17.208 → 21.931 |

Each validated echo includes transmission and reception. The driver
counts include the test harness and echo handling. The packet-size
matrix reduced allocations in every case, while p99 varied and exceeded
the proposed 10% budget in some cases. The evidence includes GC cycles,
CPU, latency, loss, and memory for all 48 windows. [Raw sanitized samples](evidence/native-load-full-power-2026-11-27.jsonl)

Separate profiles of the same 64-tunnel mixed workload measured cumulative
mutex delay attributed to `Session.write` at 4.56 → 9.39 ms for UDP and
1.71 → 1.17 ms for TCP. Each profile covered roughly six seconds of traffic.
The sampled `alloc_space` totals displayed by pprof over each complete
profiled process were 871.14 → 575.23 MB for UDP and 792.41 → 381.90 MB
for TCP.
These totals also include setup and the workload driver. Use the
per-validated-echo counts above for comparisons with different delivery rates.
The two transports moved in different directions. The single-vCPU results
and the workstation profiles support retaining the atomic key transition
in the shared mutex until synchronized tests on more cores establish the
cause of the tail latency changes.

In the unrestricted reconnect test with Community 2.6.23, all 64, 256
and 1,000 TCP tunnels recovered after a shared peer restart. In-flight
attempts never exceeded eight, the queue rejected none, and all admission
slots were released. The test also verified traffic after recovery and
a scheduled rekey across all 64 tunnels in the first case.

| Tunnels | Recovery p50/p95/p99 (ms) | Peak waiting | Failed attempts | Driver CPU (s) | RSS (MiB) | FDs |
|---:|---:|---:|---:|---:|---:|---:|
| 64 | 141 / 212 / 213 | 56 | 0 | 0.087 | 29.0 | 73 |
| 256 | 382 / 744 / 764 | 248 | 0 | 0.398 | 82.1 | 265 |
| 1,000 | 1,675 / 3,226 / 3,366 | 992 | 54 | 1.832 | 288.2 | 1,009 |

Run `TestConcurrentReconnectAdmission` in an isolated loopback-only
namespace with `OPENVPN_RECONNECT_LOAD=1`. Set
`OPENVPN_RECONNECT_SESSIONS` for the desired count and
`OPENVPN_RECONNECT_REKEY=1` for the timed rekey case. Shared DNS-timeout,
authentication rejection and server-initiated rekey stress at that scale
remain pending.

On 2026-11-27, the earlier paced soak was superseded by an unrestricted
24-hour run with 64 UDP tunnels, normal scheduling priority, 240 windows
of 360 seconds, and no request pacing. It requests timed rekeys every
60 seconds and restarts the local peer after every 20 windows. The run
entered its traffic phase. The 24-hour result and 72-hour run remain
qualification gates.
