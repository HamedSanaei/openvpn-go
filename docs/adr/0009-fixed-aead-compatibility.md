# ADR 0009 · Explicit fixed AEAD compatibility

The default requires an authenticated cipher selection, TLS exporter
derivation and a valid peer ID for DATA_V2. Certificate trust, endpoint
identity, pins, CRLs, and TLS 1.2 or later apply across connection modes.
Authentication failures and transport timeouts do not select a data mode.

The isolated RouterOS CHR 7.25.2 test sends an initial plain server
reset with zero acknowledgements, followed by a standalone ACK for
client reset zero. The client can accept this framing by requiring both
packets from the same peer session and the ACK to name the client's
random session ID. It repeats client reset zero with the server reset
ACK attached. This is control framing only. TLS and data negotiation
requirements are identical for either reset exchange. Protected
initial resets and soft-reset validation keep their existing rules.

The resulting fixed AEAD policy is scoped to each explicit endpoint.
It selects exactly one AES-GCM cipher and requires a client
certificate. This compatibility fixture implements plain outer
control with verified TLS. The authenticated server key-method-2
message has the two random fields and one options field. It must
declare the selected cipher exactly once. The normal reader still
requires its existing metadata fields. The verified push must contain
a valid DATA_V2 peer ID. An explicit cipher in the push must match the
options and configuration. An exporter or unrecognized protocol flag
conflicts with the selected policy. The fixed client advertises DATA_V2
and its one cipher and omits the exporter capability.

Classic key derivation uses two RFC 2246 PRF expansions. The
`OpenVPN master secret` label and the client/server first randoms
derive a 48-byte secret from the client premaster. The
`OpenVPN key expansion` label, second randoms and client/server
control session IDs derive the two 128-byte directional slots from
that secret. The labels have no trailing space. The wire draft prose
identifies both control session IDs, while its example omits them
and gives inconsistent key expansion arguments. OpenVPN's published
definitions corroborate these wire parameters. The OpenSSL vector
test independently checks the PRF output and direction mapping.

The client retains the entropy only within that verified control
handshake. Every initial or soft-reset generation uses fresh
entropy, with temporary key material cleared on return. The
authenticated data channel keeps the same DATA_V2 packet layout,
AEAD nonces, replay protection, packet cap and retiring-key overlap.
The legacy PRF requires HMAC-MD5 and HMAC-SHA1 and is disabled in
Go FIPS mode. It never selects an older TLS version or weaker data
cipher. The fixed path is separate from the default TLS exporter
and is never inferred from a name, error or omission.
[OpenVPN wire draft](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html) · [RFC 2246 §5](https://www.rfc-editor.org/rfc/rfc2246#section-5) · [OpenVPN published PRF parameters](https://build.openvpn.net/doxygen/ssl_8c_source.html) · [RouterOS OpenVPN](https://help.mikrotik.com/docs/spaces/ROS/pages/2031655/OpenVPN)
