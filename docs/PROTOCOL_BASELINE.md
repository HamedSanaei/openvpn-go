# OpenVPN protocol baseline

This document records the public protocol facts that shape the implementation. It is not a substitute for the complete protocol specification. Each item must be validated by tests against official OpenVPN releases.

## Wire transport

- OpenVPN can carry protocol packets over UDP or TCP.
- UDP preserves packet boundaries: one UDP payload represents one OpenVPN packet.
- TCP uses a 16-bit packet-length prefix in network byte order, followed by the OpenVPN packet.
- The protocol packet begins with an opcode/key-id byte. The high five bits identify the opcode and the low three bits identify the key generation.
- Control and data traffic are multiplexed over the same connection.

## Control channel

- The control channel establishes and maintains the TLS session and carries configuration/authentication/key negotiation.
- Control packets have session identifiers, packet identifiers and optional acknowledgement information.
- Control-channel reliability uses acknowledgements and retransmission over transports that do not guarantee delivery.
- Control and data channels maintain distinct packet-ID/replay state.
- The implementation must treat session IDs, key IDs, packet IDs and acknowledgements as untrusted wire input.

## Data channel

- The data channel carries encrypted tunnel packets, typically IP packets.
- Data-channel cipher negotiation must be constrained by an explicit allow-list.
- AEAD packet formats include nonce/IV construction, packet IDs and authentication tags; all must match the negotiated OpenVPN mode exactly.
- Key generations must be selected by key ID and retired only according to protocol-defined transition rules.
- Replay protection must be applied before delivering decrypted packets to the tunnel.

## TLS and control-channel protection

- TLS provides peer authentication and establishes the control channel.
- tls-auth adds shared-key HMAC authentication to control packets.
- tls-crypt authenticates and encrypts control-channel packets.
- tls-crypt-v2 uses client-specific wrapped keys and has additional key/metadata handling.
- These modes are not interchangeable; the parser and handshake must preserve the selected mode and key direction.

## Profile and endpoint behavior

The official OpenVPN manual documents multiple remotes, connection blocks, per-connection protocol/port settings, TLS options, inline files and authentication options. The parser must model effective connection settings rather than treating all remote lines as a single undifferentiated list.

## Compatibility policy

Initial target:
- OpenVPN TLS client mode.
- UDP and TCP.
- TLS 1.2/1.3 where supported by the peer and Go TLS stack.
- Key method 2.
- AEAD data-channel modes supported by the declared cipher allow-list.
- tls-auth, tls-crypt and tls-crypt-v2, delivered in milestone stages.

Do not claim compatibility for a directive or protocol mode until there is an interoperability test and a documented version range.

## Important caveat

The OpenVPN Wire Protocol document linked below is published as work in progress. It is a valuable protocol reference, but not the only conformance authority. Cross-check the official OpenVPN manual, official implementation behavior and real interoperability tests.

## Public references

1. OpenVPN Wire Protocol (work in progress): https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html
2. OpenVPN network protocol documentation: https://build.openvpn.net/doxygen/network_protocol.html
3. OpenVPN 2.6 manual: https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/
4. OpenVPN TLS options: https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/tls-options.rst
5. OpenVPN Access Server configuration overview: https://openvpn.net/as-docs/configuration/

## Protocol research checklist

- [ ] Confirm exact TCP framing and maximum packet length behavior.
- [ ] Confirm all required client reset/control opcodes for the target server matrix.
- [ ] Specify ACK/retransmit timing, queue bounds and duplicate handling.
- [ ] Specify TLS-auth packet layout and HMAC digest behavior.
- [ ] Specify tls-crypt and tls-crypt-v2 key wrapping/metadata behavior.
- [ ] Specify key method 2 derivation and peer-info negotiation.
- [ ] Specify each supported AEAD packet format, nonce and packet-ID layout.
- [ ] Specify key-ID rollover and overlapping key-generation behavior.
- [ ] Specify auth-user-pass and certificate authentication sequence.
- [ ] Specify remote/connection block inheritance and per-remote option precedence.
