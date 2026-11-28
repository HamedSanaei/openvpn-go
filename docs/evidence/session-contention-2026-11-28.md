# Session contention on a multicore host

Issue #114 evaluated splitting the session lock into separate send and
receive ownership. Keep the shared lock on the measured path. The two
directions and rekey share the active and retiring key snapshot, and the
measured delay does not justify a new synchronization scheme.

## Workload and results

The baseline is `417ca17e939c563376383908e72ae6ded434088b` on WSL2 Linux
`6.18.33.2-microsoft-standard-WSL2`, with an i5-13450HX, 16 visible
logical CPUs, Go 1.26.11, automatic Go parallelism and CGO disabled. The
isolated loopback peer was signed Community 2.6.23 (binary SHA-256
`58e2af67cfff115f977540b30f6d0ff9bb87ca513f9f28974b1b529d32cbb1d1`).
Each synthetic UDP application packet made a complete trip through the
client and peer and back. The driver used four outstanding requests per
tunnel, unpaced, with a one-second warmup, three four-second measured
windows and a four-second client rekey interval.

Goodput and p99 are medians of the three windows. The delay columns show
cumulative mutex-owner delay attributed to the full send and receive
call stacks over the profiled run. These include other locks in the
same stack, such as transport and queue locks. A dash marks a stack
that did not appear in the sampled profile.

| Transport | Tunnels | Inner packet bytes | Goodput (Mbit/s) | p99 RTT (ms) | Median loss | Send delay (ms) | Receive delay (ms) |
|---|---:|---|---:|---:|---:|---:|---:|
| TCP | 1 | 64 | 7.63 | 0.401 | 0.004% | 0.373 | — |
| TCP | 1 | 1,400 | 233.24 | 0.453 | 0.005% | 0.384 | 0.017 |
| TCP | 64 | 64 | 22.29 | 5.778 | 0.082% | 20.929 | 18.010 |
| TCP | 64 | Mixed | 358.09 | 6.931 | 0.117% | 64.698 | 156.544 |
| UDP | 1 | 64 | 5.27 | 0.511 | 0.005% | 0.637 | 0.514 |
| UDP | 1 | 1,400 | 157.20 | 1.124 | 0.007% | 1.873 | 0.093 |
| UDP | 64 | 64 | 23.07 | 6.523 | 0.079% | 7.169 | 3.919 |
| UDP | 64 | Mixed | 482.79 | 5.778 | 0.203% | 11.055 | 5.812 |

Every tunnel exchanged authenticated traffic. The runs averaged three
successful rekeys per tunnel, with no reconnects. The 64-tunnel profiles
showed at most 0.27% of sampled mutex delay in either call stack.
In the 64-tunnel mixed UDP run, the mutex profile attributed 355 µs
to the unlock after sealing and less than 1 µs to the unlock after
receiving. The block profile attributed 0.14–0.20 ms to the entire
send stack for each 64-tunnel case. CPU samples in the 64-tunnel
send stack included 3.78–5.50 seconds in the transport write.

A separate two-second scheduler trace of 64 UDP tunnels with 64-byte
packets showed 2.19 aggregate seconds of runnable delay. Channel sends
accounted for 441 ms and nonblocking channel sends for 130 ms in the
trace. Runtime scheduling delay, CPU time, sampled lock-owner delay
and successful-echo RTT measure different events. In particular,
aggregate lock delay cannot be used as a per-packet RTT estimate.

This experiment exercises one synthetic echo workload on a virtual host.
Revisit the locking decision if a controlled workload with independent
send and receive generators repeatedly attributes a substantial part of
tail latency to the session lock. A change would need to preserve
packet ID and nonce ordering, replay commitment, the retiring-key bound
and fragment lifetime.

`go test -race ./...` and `go vet ./...` passed on the baseline.
Isolated TCP and UDP interoperability also passed the server-initiated
rekey, local key-ID rollover and lost-final-ACK cases with signed
Community 2.6.23 and 2.7.9.

## Reproduce

Run from the baseline on an isolated Linux host with a signed Community
peer at `$PEER` and a private output directory `$OUT` outside the source
tree. The output directory for each invocation must be new.

~~~sh
for network in tcp udp; do
    for spec in '1 64' '1 1400' '64 64' '64 mixed'; do
        read -r tunnels packets <<< "$spec"
        target="$OUT/$network-$tunnels-$packets"
        OPENVPN_INTEROP_VERSION=2.6.23 OPENVPN_LOAD_PROFILE=1 \
        OPENVPN_LOAD_NETWORK="$network" OPENVPN_LOAD_SESSIONS="$tunnels" \
        OPENVPN_LOAD_PACKETS="$packets" OPENVPN_LOAD_REKEY=4 \
        OPENVPN_LOAD_WARMUP=1 OPENVPN_LOAD_WINDOWS=3 OPENVPN_LOAD_SECONDS=4 \
            bash tests/interop/native-load.sh "$PEER" "$target"
        go tool pprof -top -cum "$target/mutex.pprof"
        go tool pprof -list='internal/session\.\(\*Session\)\.(write|receive)' "$target/mutex.pprof"
        go tool pprof -top -cum "$target/block.pprof"
        go tool pprof -top -cum "$target/cpu.pprof"
    done
done
~~~

For scheduler attribution, run the same isolated driver with
`-test.trace` and extract runnable delay with `go tool trace -pprof=sched`.
[Native load setup](../NATIVE_LOAD.md)
