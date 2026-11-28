# Linux UDP batching and TCP frame writes

The portable transport stays the shipped implementation. The Linux
UDP primitive shows a useful CPU and syscall reduction when full batches
are already available. Larger batches raise service latency even in that
case. The TCP vector-write experiment shows little difference in
throughput and inconsistent changes in tail latency.

## Socket-level evidence

The benchmark ran on WSL2 Linux `6.18.33.2-microsoft-standard-WSL2`,
Intel i5-13450HX and Go 1.26.11 with 16 visible logical CPUs. Each row
reports the median of five isolated 400-ms samples.

UDP sends synthetic datagrams to a loopback socket with
`sendmmsg` and reads them back with `recvmmsg`. Batches hold 1, 8, 16 or
32 datagrams. CPU includes the entire benchmark process. The p99
measures service of a preassembled batch including sending and reading,
and excludes time spent collecting packets into the batch. Socket calls
per packet include attempts that encounter `EAGAIN`.

| UDP bytes | Batch | MB/s | CPU s/Gbit | Socket calls per packet | Batch p99 (µs) |
|---:|---:|---:|---:|---:|---:|
| 64 | 1 | 16.24 | 10.470 | 2.0000 | 12.56 |
| 64 | 8 | 27.63 | 6.023 | 0.2500 | 31.23 |
| 64 | 16 | 35.70 | 5.292 | 0.1250 | 47.44 |
| 64 | 32 | 41.11 | 4.937 | 0.0625 | 101.90 |
| 256 | 1 | 65.27 | 2.600 | 2.0000 | 12.82 |
| 256 | 8 | 110.55 | 1.507 | 0.2500 | 32.17 |
| 256 | 16 | 139.95 | 1.343 | 0.1250 | 59.13 |
| 256 | 32 | 165.44 | 1.236 | 0.0625 | 99.73 |
| 1,400 | 1 | 350.81 | 0.481 | 2.0000 | 12.89 |
| 1,400 | 8 | 580.46 | 0.289 | 0.2500 | 36.52 |
| 1,400 | 16 | 742.79 | 0.254 | 0.1250 | 53.77 |
| 1,400 | 32 | 860.14 | 0.237 | 0.0625 | 100.20 |

The TCP benchmark sends one length-prefixed frame per iteration and
reads its echo. Both write paths allocated zero bytes per iteration.

| TCP bytes | Copy MB/s | Scatter/gather MB/s | Copy / scatter-gather p99 (µs) |
|---:|---:|---:|---:|
| 64 | 12.58 | 12.44 | 9.44 / 8.38 |
| 256 | 49.71 | 49.84 | 10.01 / 9.44 |
| 1,400 | 258.69 | 259.50 | 8.84 / 9.57 |

The UDP primitive test verifies datagram ordering, a partial result,
truncation reporting and interruption of an empty read by its
deadline. The transport, data and session race tests passed.

## Adoption decision

Keep the experiment outside the runtime. The socket-level gain is a
reason to continue evaluating receive batching. The integrated
comparison still needs packet-level p99 including fill time, control
and rekey service under load, fairness across connections and verified
drop rates. The available TCP scatter/gather measurements do not
justify switching from the current framed write.
[Authenticated native baseline](session-contention-2026-11-28.md)

~~~sh
go test -race ./transport ./internal/session ./internal/data
go test ./transport -run '^TestLinuxUDPBatchDatagramBoundaries$' \
    -bench 'BenchmarkLinuxUDPBatch|BenchmarkTCPFrameWrites' \
    -benchtime 400ms -count 5
~~~
