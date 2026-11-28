# Native soak fixture expiry and seed 29

The previous 64-tunnel, unpaced UDP soak used 360-second windows and
certificates minted with a one-hour validity. The job finished ten
full-traffic windows, sent 2,430,844 packets in window 11, and had zero
sent or received packets in window 12. The driver reported certificate
verification failure during rekey or reconnect. The run terminated
after 4,321 seconds. This run did not qualify 24-hour stability.

Revision `c306fad` adds synthetic certificates for the entire planned
workload, with time for setup and peer restarts. A test verifies both
server and client certificate chains at the final planned 72-hour
rekey, and verifies that they are rejected after expiry.

The eight-tunnel short stress gate passed against signed Community
2.6.23 and 2.7.9 on WSL2 under the race detector, and with Community
2.6.23 on the dedicated two-vCPU test host. The gate included one
peer restart, a two-second rekey interval and verified tunnel echoes.
A fresh 64-tunnel, 24-hour run with Community 2.6.23 was started on
the dedicated host using the same configuration as the failed run.
Only the short gate has a completed result. The full 24-hour and
72-hour results are still required.

## Separate seeded loss workload

The two-client, 96-packet seed-29 test passed with signed Community
2.6.23 and 2.7.9. With four clients and 400 packets per client, three
isolated race-enabled attempts with 2.6.23 each timed out waiting for
key ID 2 on lease 3 after successfully installing key ID 1. Two of
three attempts passed with 2.7.9. The remaining attempt had the same
key-ID timeout. The relay applies each lease's derived seed to that
run's arrival order. The failure of the wider workload remains open.

~~~sh
OPENVPN_LOAD_SESSIONS=8 OPENVPN_LOAD_REKEY=2 OPENVPN_LOAD_RESTART_EVERY=2 \
    bash tests/interop/native-load.sh "$PEER" "$SHORT_REPORT"

OPENVPN_LOAD_SESSIONS=64 OPENVPN_LOAD_SECONDS=360 OPENVPN_LOAD_WINDOWS=240 \
    OPENVPN_LOAD_REKEY=60 OPENVPN_LOAD_RESTART_EVERY=20 \
    bash tests/interop/native-load.sh "$PEER" "$DAY_REPORT"
~~~

Use 720 windows for the 72-hour qualification workload.
[Native workload and evidence requirements](../NATIVE_LOAD.md)
