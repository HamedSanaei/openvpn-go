# Fuzzing plan

Fuzz targets will cover all parsers and decoders that accept untrusted bytes or files:

- OVPN profile parser and inline block parser.
- TCP length-prefixed frame decoder.
- OpenVPN packet header/opcode/key-id decoder.
- Control packet decoder and ACK list.
- Data packet decoder and replay-window logic.

Every target must enforce packet/profile size limits and avoid unbounded allocations, recursion or goroutine creation. Add regression tests for every discovered crash or panic. Long-running fuzz campaigns are a release gate.
