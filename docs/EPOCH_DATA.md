# OpenVPN 2.7 epoch data evaluation

OpenVPN Community 2.7 can negotiate a data-channel format that rotates
traffic keys through epochs within one control-channel key generation.
That mechanism is distinct from the classic three-bit key ID used when
the control channel rekeys. The peer advertises epoch capability in
peer information. The server selects it in authenticated push options
using the `aead-epoch` protocol flag.
[OpenVPN 2.7 status](https://community.openvpn.net/Development/StatusOfOpenvpn27) · [OpenVPN 2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual/) · [Tagged protocol definitions](https://github.com/OpenVPN/openvpn/blob/v2.7.9/src/openvpn/ssl.h)

## Observed behavior

- Signed Community 2.7.9 peers selected `aead-epoch` and established the
  reference session over TCP with TLS 1.2 and AES-256-GCM.
- The Go client completed the classic TLS exporter and DATA_V2 traffic
  matrix against the same server version. Classic rollover retained data
  traffic.
- A 2.7.9 server forced `aead-epoch` into its authenticated push. The Go
  client rejected negotiation before publishing a session.

The default stays with classic exporter-based AEAD. The Go client
advertises capabilities it implements and accepts their corresponding
authenticated options. It treats unsolicited epoch selection as a
protocol error. The reference comparison verifies negotiation only.
[Negotiation tests](../tests/interop/version_policy_test.go) · [Compatibility matrix](COMPATIBILITY_MATRIX.md#openvpn-community-279)

## Security requirements for future implementation

| Risk | Required behavior |
|---|---|
| Downgrade and format confusion | Select the exact data format from authenticated negotiation before forwarding. Bind the selection to the control generation. Reject contradictory flags and invalid cipher combinations. |
| Nonce or key reuse | Separate transmit and receive keys and control generations. Derive epoch keys with the specified labels and encoding. Enforce per-cipher packet and byte bounds, and stop before epoch or packet counters exhaust. |
| Replay across epochs | Authenticate before committing replay or epoch state. Keep a bounded previous-epoch overlap for valid reordering. Reject duplicates and packets outside the overlap. |
| Resource exhaustion | Bound forward epoch lookahead and derivation work from unauthenticated headers. Reject invalid lengths, IDs and epoch jumps without allocating unbounded state or advancing a replay window. |
| Rekey and parallel send | Serialize nonce allocation and publish key transitions atomically. Clear retired keys after their bounded receive window, and clear all session keys on teardown. |

Before activation, verify independently generated fixtures for directional
key derivation, wire format, AAD and nonces, first and last packets at
rollover, tampered headers and tags, skipped epochs, replay and exhaustion.
Then exercise real 2.7 peers in both traffic directions across epoch
rollover and classic control-generation rekey. Include reordered and
dropped packets, an unexpected flag, corrupted packets and a peer that
supports only classic data. The current reference test and classic
rollover evidence leave those epoch data-path cases for the implementation.
