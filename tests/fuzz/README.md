# Fuzzing

Run the decoder smoke tests and sustained campaigns with the pinned Go toolchain.

~~~sh
make fuzz-smoke
make fuzz
FUZZ_TIME=2m sh tests/fuzz/run.sh FuzzTCPFrame
~~~

The profile seeds include generated PKI, inline credentials and wrapped key
material, connection blocks and malformed syntax. The target checks that
errors return a zero configuration and that every accepted configuration
can construct a client. Regular Go tests also run all seed cases.

The suite exercises profile syntax, TCP length framing, control packet headers
and ACK fields, control packet authentication, DATA_V2 authentication and replay,
and multipart TLS push options. Test credentials and protection keys are
synthetic. Keep any resulting failure corpus private while a finding is triaged.
The initial sustained run is recorded in the [hardening evidence](../../docs/HARDENING.md).

Every target must enforce packet/profile size limits and avoid unbounded allocations, recursion or goroutine creation. Add regression tests for every discovered crash or panic. Long-running fuzz campaigns are a release gate.
