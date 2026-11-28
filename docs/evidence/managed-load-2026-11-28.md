# Authenticated load through the session manager

The [native workload](../NATIVE_LOAD.md) can run through the manager's public
`NewWithResources` and `StartWithResources` APIs. Set
`OPENVPN_LOAD_MANAGED=1` and select a tunnel count with
`OPENVPN_LOAD_SESSIONS`. Each lease uses an in-memory packet device,
one reserved transport descriptor, a separately declared packet-buffer
reservation for the device, and a shared handshake limiter with eight
active attempts. The manager and limiter must release their reservations
after cancellation. The report identifies the managed workload and records
the least and most echoes delivered by any tunnel during each window.
Per-lease rekey reports are available in the direct-client workload.

## Two-vCPU lab

The candidate was `df2b91aeb2c683ea806eb683a058847ec8b71afc` on a
two-vCPU AMD EPYC Rome KVM guest running Linux `7.0.0-44-generic` and
Go 1.26.11. The signed Community 2.6.23 peer had SHA-256
`bfb3a8d2b252b11f6db0e682b93f27e980842e23ea4b028d3aa9fb8bc06d1fef`.
All traffic was inside a disposable loopback namespace at normal
scheduling priority and without pacing. Each combination used a
one-second warmup and three three-second mixed 64/256/1,400-byte windows.

The table reports median goodput, p99 RTT and loss across windows.
The minimum echo count is across all individual tunnels and windows.
The resource columns show peak measurements at the window boundaries
for the driver, which includes the in-process echo and load generators.
The peer and kernel have separate resource costs.

| Transport | Tunnels | Goodput (Mbit/s) | p99 (ms) | Loss | Min echoes | Peak silent tunnels | RSS / heap / stacks (MiB) | FDs | Goroutines | Queue high-water (packets) |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|---:|
| TCP | 64 | 257.72 | 7.36 | 0.83% | 333 | 0 | 35.44 / 21.53 / 3.59 | 74 | 709 | 5 |
| TCP | 128 | 204.17 | 16.20 | 2.93% | 71 | 0 | 58.56 / 34.01 / 6.84 | 138 | 1,413 | 4 |
| TCP | 256 | 224.30 | 20.64 | 5.72% | 44 | 0 | 106.04 / 87.20 / 12.69 | 266 | 2,821 | 4 |
| TCP | 512 | 188.04 | 29.70 | 13.35% | 19 | 0 | 197.86 / 169.32 / 24.56 | 522 | 5,637 | 5 |
| TCP | 1,000 | 188.14 | 69.39 | 24.76% | 9 | 0 | 374.66 / 264.88 / 48.84 | 1,010 | 11,005 | 5 |
| UDP | 64 | 289.48 | 9.39 | 0.95% | 1,037 | 0 | 38.90 / 22.18 / 3.66 | 74 | 709 | 4 |
| UDP | 128 | 312.79 | 9.97 | 2.61% | 176 | 0 | 64.53 / 50.35 / 6.62 | 138 | 1,413 | 4 |
| UDP | 256 | 250.72 | 17.21 | 6.95% | 64 | 0 | 120.25 / 105.53 / 12.56 | 266 | 2,821 | 5 |
| UDP | 512 | 268.10 | 26.31 | 14.10% | 8 | 0 | 229.02 / 151.64 / 24.84 | 522 | 5,637 | 7 |
| UDP | 1,000 | 283.30 | 27.95 | 24.14% | 0 | 10 | 426.47 / 298.80 / 48.56 | 1,010 | 11,005 | 5 |

The driver used a median of 1.03–1.07 CPU seconds per elapsed second.
All manager reservations and handshake permits were released. Each run
returned to two goroutines. Descriptor snapshots went from four before
setup to six after final cleanup.

The separate 64-tunnel UDP churn run used seven four-second windows,
three peer restarts and a four-second rekey interval. All 64 leases
resumed after each restart. Minimum validated echoes per tunnel and
window were 918. Recovery p99 was 2.98 s, 0.94 s and 2.98 s. RSS reached
47.09 MiB, and the window-boundary descriptor count rose from 74 to 77.
After cleanup only six descriptors remained. Longer churn runs are
needed to classify the rising in-run descriptor snapshots.

For this guest and workload, 64 tunnels was the largest tested setting
with less than 1% median loss on both transports. A deployment with
stricter loss or p99 objectives needs its own measured cap and resource
budgets. A configured lease is one authenticated tunnel with a bounded
device and transport reservation. Application flow capacity within one
tunnel is measured separately.
