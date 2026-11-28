# Shared handshake admission through endpoint outages

The lab ran `6f348be` on a two-vCPU AMD EPYC Rome KVM guest, Linux
`7.0.0-44-generic` and Go 1.26.11 with CGO disabled. It used signed
Community 2.6.23 (SHA-256
`bfb3a8d2b252b11f6db0e682b93f27e980842e23ea4b028d3aa9fb8bc06d1fef`)
inside a loopback-only network namespace. All clients shared eight
handshake slots, with a wait bound equal to the number of clients.
This tested one burst per combination at normal scheduling priority.

After disconnecting the peer, the test injects a cancellable,
100-millisecond DNS resolution or socket dial timeout into every client.
It confirms the failure stage before restoring the peer. The peer-rekey
case confirms every client's next connection installed a key from a
peer-initiated exchange. The successful cases also verify real tunnel
echoes from the first and last client after recovery.

| Scenario | Clients | Recovery p50 / p95 / p99 (ms) | Attempts / failures | Peak waiters | Driver CPU (s) | RSS (MiB) | FDs |
|---|---:|---|---|---:|---:|---:|---:|
| Resolution timeout | 64 | 151 / 357 / 414 | 200 / 72 | 56 | 0.115 | 31.1 | 73 |
| Resolution timeout | 256 | 268 / 431 / 444 | 776 / 264 | 248 | 0.333 | 91.3 | 265 |
| Resolution timeout | 1,000 | 823 / 1,541 / 1,602 | 3,008 / 1,008 | 986 | 1.444 | 282.9 | 1,009 |
| Socket timeout | 64 | 152 / 394 / 473 | 200 / 72 | 56 | 0.118 | 31.4 | 73 |
| Socket timeout | 256 | 280 / 463 / 473 | 776 / 264 | 248 | 0.366 | 85.4 | 265 |
| Socket timeout | 1,000 | 850 / 1,531 / 1,586 | 3,008 / 1,008 | 992 | 1.437 | 277.5 | 1,009 |
| Restart and peer rekey | 64 | 106 / 146 / 147 | 128 / 0 | 56 | 0.103 | 28.7 | 73 |
| Restart and peer rekey | 256 | 241 / 389 / 405 | 512 / 0 | 240 | 0.346 | 86.9 | 265 |
| Restart and peer rekey | 1,000 | 763 / 1,465 / 1,519 | 2,000 / 0 | 973 | 1.458 | 276.6 | 1,009 |

In the separate authentication case each client had one previously
working connection. After restart the same verified peer rejected
credentials. Each client reported one terminal authentication failure
and left its reconnect loop without publishing a replacement session.
The batches of 64, 256 and 1,000 finished rejecting credentials in
200 ms, 702 ms and 2.69 s, respectively.

All cases reached eight active slots, never exceeded the wait budget,
and ended with zero permits held, zero queued waiters and zero
admission rejections. These counts reflect the selected queue size.
Tighter admission queues and locally initiated rekey timing have
separate regression requirements in #128 and #127. Provider-specific
qualification remains tracked in #49.

## Reproduce

Build the interop test and use an absolute path for the signed peer and
for the test binary. Run each scenario in its own disposable namespace.

~~~sh
go test -c -o "$TEST_BINARY" ./tests/interop
for mode in resolve dial authentication peer-rekey; do
    for count in 64 256 1000; do
        sudo -n env OPENVPN_INTEROP_BIN="$PEER" OPENVPN_INTEROP_VERSION=2.6.23 \
            OPENVPN_RECONNECT_LOAD=1 OPENVPN_RECONNECT_FAILURE="$mode" \
            OPENVPN_RECONNECT_SESSIONS="$count" \
            unshare --net --pid --fork --kill-child --mount-proc \
                sh -c 'ip link set lo up; exec "$@"' sh "$TEST_BINARY" \
                -test.run '^TestConcurrentReconnectAdmission$' -test.v -test.timeout=140s
    done
done
~~~

The same four scenarios at eight tunnels passed under the race
detector. The regular client tests cover FIFO waiting and cancellation
with a simulated clock.
