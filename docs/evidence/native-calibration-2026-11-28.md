# Same-revision native load calibration check

The matrix compared `6e04b06` with itself using a pinned Community
2.6.23 peer on WSL2 Linux amd64, Go 1.26.11 and an i5-13450HX. Both
runs of each case used one tunnel, one warmup second and three
two-second windows. This was a smoke check of the comparison method
and report collection.

| Workload | Goodput A / B (Mbit/s) | CPU s/Gbit A / B | p99 RTT A / B (ms) | Gate result |
|---|---:|---:|---:|---|
| TCP 64 | 9.84 / 9.88 | 98.04 / 98.63 | 0.262 / 0.247 | p99 variance |
| TCP 256 | 64.66 / 65.75 | 14.89 / 14.84 | 0.232 / 0.262 | p99 variance |
| TCP 1,400 | 305.70 / 320.79 | 3.23 / 3.14 | 0.296 / 0.296 | Pass |
| TCP mixed | 204.89 / 201.39 | 4.94 / 4.99 | 0.279 / 0.296 | Pass |
| UDP 64 | 10.16 / 11.35 | 102.28 / 90.62 | 0.334 / 0.219 | p99 variance |
| UDP 256 | 73.13 / 72.29 | 14.18 / 14.57 | 0.219 / 0.232 | Pass |
| UDP 1,400 | 401.10 / 380.44 | 2.72 / 2.92 | 0.262 / 0.334 | p99 change exceeded 10% |
| UDP mixed | 228.41 / 224.54 | 4.70 / 4.70 | 0.247 / 0.262 | Pass |

All eight cases produced complete reports. The command exited nonzero
because four cases exceeded the fixed p99 criteria. Preserve that
behavior on the dedicated runner. Calibrate with longer repeated
windows on the target hardware before setting release budgets. The
repository has no registered self-hosted runner, so nightly calibration
and physical-NIC results remain pending.
[Workflow and reproduction](../NATIVE_LOAD.md)
