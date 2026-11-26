# OpenVPN 2.6 client protocol baseline

M0 specifies the client behavior for the exact peer and modes in the
[compatibility matrix](COMPATIBILITY_MATRIX.md). M1–M6 implement and verify it.
Integer wire fields are unsigned and big-endian. In the layouts below, `|`
means byte concatenation, `uN` is an N-bit field and brackets indicate a
conditional field.

## Transport and dispatch

UDP carries one complete OpenVPN packet per datagram. Reject empty, truncated
or oversized datagrams before decoding. TCP carries `u16(length) | packet`,
where the length excludes its own two bytes. Read the prefix and body
completely, preserve partial-write handling and serialize frame writes.
A zero length, a frame beyond the configured receive cap, or EOF inside a frame
closes the stream. The prefix can represent up to 65,535 bytes. Apply the
local cap before allocating or reading the body in either transport.
[Wire draft §§3–4](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-3) · [Network protocol](https://build.openvpn.net/doxygen/network_protocol.html)

The packet starts with `H = (opcode << 3) | key_id`. The dispatcher validates
the direction, phase and generation as well as the opcode.

| Opcode | Name | Client behavior |
|---|---|---|
| 3 | `P_CONTROL_SOFT_RESET_V1` | Send or receive during rekey |
| 4 | `P_CONTROL_V1` | Send or receive reliable TLS stream bytes |
| 5 | `P_ACK_V1` | Send or receive acknowledgements |
| 6 | `P_DATA_V1` | Defined below for reference, outside the required DATA_V2 matrix |
| 7 | `P_CONTROL_HARD_RESET_CLIENT_V2` | Send initial reset in plain TLS, tls-auth or tls-crypt |
| 8 | `P_CONTROL_HARD_RESET_SERVER_V2` | Receive initial reset reply |
| 9 | `P_DATA_V2` | Send or receive negotiated AEAD data with peer ID |
| 10 | `P_CONTROL_HARD_RESET_CLIENT_V3` | Send initial reset with tls-crypt-v2 |
| 11 | `P_CONTROL_WKC_V1` | Send the cookie handshake continuation when requested and valid |

Legacy reset opcodes 1 and 2 and extensions outside the pinned profile are
unsupported. Use the published opcode definitions for numeric values. The
network protocol overview's generated link numbers are reference markers.
[Opcode definitions](https://build.openvpn.net/doxygen/ssl__pkt_8h.html)

## Control packet layouts and reliability

`SID` is the 8-byte sender session ID. Generate the local ID with a
cryptographic RNG on each full connection attempt and latch the peer's ID
only on a valid initial reply for the active attempt. A reset received during
an established session never replaces the peer or resets replay state.
A soft reset keeps the two session IDs and creates new TLS and reliability
state. [Wire draft §6.2](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-6.2)

| Field sequence | Layout |
|---|---|
| ACK section | `u8(count) \| count * u32(ack_id) \| [8-byte target SID if count > 0]` |
| Control body | `ACK section \| [u32(message_id) \| payload for non-ACK opcodes]` |
| TLS without outer protection | `H \| SID \| control body` |
| tls-auth | `H \| SID \| digest-sized MAC \| outer replay ID \| control body` |
| tls-crypt | `H \| SID \| outer replay ID \| 32-byte tag \| encrypted control body` |
| tls-crypt-v2 | tls-crypt layout, with opaque wrapped key appended to opcode 10 and authorized opcode 11 only |

The outer replay ID is `u32(counter) | u32(timestamp)`. Reliable message IDs
start at zero in each direction for each generation. ACK-only packets carry
one or more ACK IDs and no message ID or TLS bytes. Reject invalid lengths,
ACK counts above eight and wrong target SIDs before updating reliability
state. Match an ACK only to a packet already sent and still outstanding
in that generation. Repeated ACKs have no effect. Validate applicable outer
authentication and replay checks before accepting the ACK section.
[Wire draft §§5–6](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-5) · [Pinned reliability definitions](https://github.com/OpenVPN/openvpn/blob/v2.6.23/src/openvpn/reliable.h) · [Packet ID API](https://build.openvpn.net/doxygen/packet__id_8h.html)

Use bounded send and reorder windows of at most 12 messages each in the
initial design. Buffer an accepted future message within the receive window
and deliver only its contiguous prefix to TLS. A duplicate already stored
or delivered may be acknowledged again within the bounded receive history.
Never deliver it twice. Drain pending ACKs into bounded ACK-only packets
when they cannot be piggybacked. ACK-only packets never elicit an ACK.
Keep the ACK and ordering logic on TCP and rely on TCP for retransmission.
Treat a partial or failed TCP write as a session I/O failure.

On UDP retransmit the same reliable ID and payload, rebuilding the wrapper
with a fresh outer replay ID when protection is configured. Start the retry
timer at two seconds, back off exponentially with a cap, and stop at the
attempt deadline or retry budget, whichever comes first. These resource and
timer settings are client policy. The receiving side keeps the wrapper replay
window separate from reliable IDs and advances it only after authenticating
the wrapper. With the same outer key and session IDs, maintain the outer
counter and replay window across soft resets. The plain outer mode uses
session and reliable sequence checks before TLS. TLS records provide
cryptographic integrity. [OpenVPN 2.6 manual, TLS options](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [Security budgets](SECURITY_MODEL.md)

## Control protection

**tls-auth.** Parse the Static key V1 envelope as two 128-byte slots, each
containing 64 cipher bytes followed by 64 authentication bytes. Direction
`0` sends with slot 0 and receives with slot 1. Direction `1` reverses them.
An omitted direction uses slot 0 both ways. Use the first digest-size bytes
of the selected slot's authentication field. Compute the full HMAC over
`outer replay ID | H | SID | control body`. Support SHA-256, SHA-384,
SHA-512 and OpenVPN's default HMAC-SHA1 for a matching legacy tls-auth
configuration. The digest setting applies to tls-auth only in this AEAD
baseline. [Wire draft §5.3 and §11.1](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-5.3) · [OpenVPN manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/)

**tls-crypt.** Static key slots have the same structure. Use the first 32
cipher bytes and first 32 authentication bytes of each slot. The client sends
with slot 1 and receives with slot 0. Compute
`tag = HMAC-SHA256(Ka, H | SID | outer replay ID | clear control body)`
and encrypt the body with AES-256-CTR using `Ke` and the first 16 tag bytes
as IV. Open into private scratch, compare the recomputed tag in constant time,
and discard failures before parsing or committing state. [Wire draft §5.4](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-5.4) · [Control protection reference](https://build.openvpn.net/doxygen/group__tls__crypt.html)

**tls-crypt-v2.** The client PEM contains the 256-byte client-specific key
material followed by the server-wrapped blob (up to 1,024 bytes). Check that
the appended big-endian length agrees with the blob size. The client uses
the client key material as the tls-crypt key, treats the blob and its metadata
as opaque, and never accepts a server wrapping key in a client profile. A
standard server blob contains an HMAC-SHA256 tag, encrypted client key and
metadata, and the trailing two-byte length. Server-side wrapping and metadata
policy are outside the client. [Wire draft §5.4.3](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-5.4.3) · [Pinned size definitions](https://github.com/OpenVPN/openvpn/blob/v2.6.23/src/openvpn/tls_crypt.h)

Start with opcode 10 under tls-crypt and append the wrapped blob. To advertise
cookie support, seed the wrapper's send counter with the `0x0f000000` marker
before the first send. The first wire counter is `0x0f000001`. Advance the
counter on every protected send in that session, including retransmissions.
Consider the resend bit only in an authenticated opcode 8 that
acknowledges the current initial reset. Decode
its bounded `u16(type) | u16(length) | value` extensions. The cookie request
uses type 1, length 2, bit 0. Reply with opcode 11 carrying the ACK for
the server reset, the next reliable message ID and the same wrapped blob.
An empty TLS payload is permitted for the continuation. Keep the same
opcode and blob on loss recovery for that message. Ignore resend requests
after initial setup, on other opcodes or from another endpoint. With no
cookie request, continue with the normal ACK and TLS flight. [Wire draft §5.4.3](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-5.4.3) · [Pinned release](https://github.com/OpenVPN/openvpn/releases/tag/v2.6.23)

## Session state and authentication

| State | Entry and allowed progress |
|---|---|
| Idle | Validate profile and choose an effective endpoint before starting network I/O. |
| Dialing | Open a bounded, cancellable transport. Allocate fresh state on success. |
| Reset | Send the initial reset with key ID 0 and reliable ID 0. Bind the peer on a valid opcode 8 with reliable ID 0 for this attempt. Complete the normal ACK or cookie path. |
| TLS handshake | Reassemble ordered control payload into a bidirectional byte stream. Use a fresh TLS configuration with endpoint-specific SNI, CA and server identity verification. Authenticate the client with its certificate and key. |
| Key exchange | Send key method 2 over verified TLS, including credentials only when configured. Validate the peer message and move to configuration. |
| Configuration | Obtain an authenticated PUSH_REPLY. Apply the allow-listed parameters after complete validation. Confirm TLS exporter, cipher and peer ID before publishing a usable data session. |
| Established | Exchange data, run keepalive and service control messages. Only authenticated valid traffic refreshes liveness. |
| Rekeying | Run a new TLS and key exchange for the next ID while receiving on the bounded previous generation. Promote the replacement atomically after successful authentication. |
| Retry or Closed | On recoverable transport failures, release resources before attempting a fresh endpoint. On authentication, identity or negotiation failures, fail with a typed terminal error. Close and cancellation take precedence in every state. |

TLS is 1.2 or 1.3. Disable TLS session resumption for the initial design so
identity and exporter initialization are explicit per generation. Treat
`AUTH_FAILED` as terminal and redact its text. Implement no credential
prompt or external auth command. [OpenVPN manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [Identity and failure policy](SECURITY_MODEL.md)

The TLS application stream starts with `u32(0) | u8(2)`, then a client-only
48-byte random field and two 32-byte random fields from each side. Generate
these compatibility fields from the system RNG. They are unused by TLS
exporter derivation. Then read or write the OCC options, username, password,
and peer-info in that order. Non-empty fields use `u16(length)` including
their trailing NUL. OpenVPN 2.6.23 emits a zero length for absent fields.
Accept that encoding and a length-one NUL for absent optional values.
Bound each field before reading it. A missing required field or embedded
NUL fails negotiation. OCC describes the effective TLS/TUN options for
compatibility checks. Peer-info includes newline-separated `IV_CIPHERS`
and `IV_PROTO` with DATA_V2 (bit 1) and TLS exporter (bit 3). No optional
privacy-sensitive device identifiers are sent. [Wire draft §§6.6–6.7](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-6.6) · [Pinned key exchange reference](https://github.com/OpenVPN/openvpn/blob/v2.6.23/src/openvpn/ssl.c)

After the key message, handle bounded NUL-terminated control commands and
send `PUSH_REQUEST` until a complete `PUSH_REPLY` or the handshake deadline.
For a split reply, collect consecutive parts marked `push-continuation 2`
until a final part marked `push-continuation 1`. A single unmarked reply
is complete on its own. Reject a missing final marker during continuation
or an unsolicited final marker. Apply no partial reply.
Require exactly one effective `cipher` from the offered allow-list, a valid
24-bit `peer-id` other than the reserved `0xffffff`, and `protocol-flags
tls-ekm` or the documented `key-derivation tls-ekm` signal. Reject conflicting
or unsupported security settings. Treat route, DNS and addressing as
validated configuration data for the embedding application. Keep pushed auth
tokens scoped to the authenticated session and its rekeys. Clear them on
failure or full reconnect and never reuse them for another endpoint.
[Wire draft §§8–9](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-8) · [OpenVPN manual, client options](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [Pinned push reference](https://github.com/OpenVPN/openvpn/blob/v2.6.23/src/openvpn/push.c)

## Data keys, packets and rekey

Use the authenticated TLS connection's exporter with label
`EXPORTER-OpenVPN-datakeys`, no context and output length 256. Split the
result into four 64-byte fields in wire derivation order:
client-to-server cipher, client-to-server implicit-IV source, server-to-client
cipher and server-to-client implicit-IV source. The client sends with the
first pair and receives with the second. Use the leading 16 cipher bytes
for AES-128-GCM and 32 for AES-256-GCM or ChaCha20-Poly1305. Each direction
uses an independent AEAD, packet counter and replay state.
[Wire draft §7.1](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-7.1) · [RFC 5705](https://www.rfc-editor.org/info/rfc5705) · [TLS 1.3 exporters, RFC 8446 §7.5](https://www.rfc-editor.org/rfc/rfc8446#section-7.5)

| Data format | Wire layout | AEAD additional data |
|---|---|---|
| DATA_V2 | `H \| u24(peer-ID) \| u32(packet-ID) \| 16-byte tag \| ciphertext` | `H \| u24(peer-ID) \| u32(packet-ID)` |
| DATA_V1 reference | `H \| u32(packet-ID) \| 16-byte tag \| ciphertext` | `u32(packet-ID)` |

The nonce in both is `u32(packet-ID) | first_8_bytes(direction IV source)`.
The VPN IP packet or protocol keepalive is AEAD plaintext. The tag precedes
ciphertext on the wire. Start data IDs at 1 and never reuse an ID with the
same key. Check generation, negotiated peer ID and packet shape, authenticate,
commit the replay decision once, then consume keepalives or deliver valid
IP packets. For UDP accept unseen reordered IDs within the bounded window.
TCP accepts strictly increasing IDs, with gaps allowed. Authentication
failures never advance the receive window. The OpenVPN data-channel
keepalive is the 16-byte value `2a187bf3641eb4cb07ed2d0a981fc748`; consume it
inside the session. Honor bounded `ping` and `ping-restart` settings with
monotonic timers. [Wire draft §7.4](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-7.4) · [Pinned keepalive reference](https://github.com/OpenVPN/openvpn/blob/v2.6.23/src/openvpn/ping.c)

Rekey on time or key-use limits, before packet ID exhaustion. Either peer
can initiate with opcode 3 under the next key ID. Respond with a soft reset
in the same generation and acknowledge it. Run TLS/key method 2 again
using the negotiated session options, without an initial PUSH_REQUEST.
Keep only the current and the retiring usable generation with a bounded
overlap, plus one pending handshake. Never select a different generation
to retry authentication of a failed data packet. Retire old state on its
deadline and clear it before key ID reuse. Move from ID 7 to 1. New initial
connections alone use ID 0. If rotation misses the old key's hard limit,
stop sending under it and close the session if a replacement is unavailable.
[Wire draft §§6.2 and 7](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#section-6.2) · [Security budgets](SECURITY_MODEL.md)

## Profile and endpoint precedence

With top-level `remote` entries, apply the final top-level connection
defaults to every entry, then apply its explicit port, protocol or address
family. With `<connection>` blocks, inherit defaults in effect at the
opening of each block. Process its directives in order, including port or
protocol supplied by its single required `remote`. Reject profiles that
mix both forms so no top-level remotes are silently discarded. Default to
UDP and port 1194 when unspecified. Preserve declared order across the
candidates. `remote-random` shuffles the complete candidate list initially,
retaining every entry. Resolve and dial with the effective transport and
address-family policy. Keep the verification identity bound to the configured
endpoint and independent of the DNS answer or proxy. Support per-endpoint
identity overrides through the embedding API and supported profile policy.
[OpenVPN manual, connection profiles and inline files](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [Pinned connection options reference](https://github.com/OpenVPN/openvpn/blob/v2.6.23/src/openvpn/options.c)

Build the M4 directive registry around `client`, `dev tun`, `remote`,
`proto`, `port`/`rport`, `remote-random`, `<connection>`, CA/cert/key,
`auth-user-pass`, the control protection options, `data-ciphers`,
`remote-cert-tls server`, `verify-x509-name` and supported TLS bounds.
Scope tls-auth, tls-crypt, tls-crypt-v2 and key direction to the effective connection
where the manual permits. Use one selected protection mode per endpoint.
Read only caller-authorized file references. Keep unsupported
security-sensitive directives fatal and report unsupported benign directives
explicitly. [OpenVPN manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [Profile security](SECURITY_MODEL.md)

## Conformance checks

The public wire draft covers newer extensions and contains inconsistencies.
This baseline takes version-specific facts from the pinned version where
needed, including absent key-method string lengths, and uses generated
OpenVPN references for named fields. M2 and M3 validate behavior with
independently generated fixtures and the pinned server. M4 validates
profile semantics against the manual. [Compatibility matrix](COMPATIBILITY_MATRIX.md) · [Acceptance criteria](TEST_STRATEGY.md)
