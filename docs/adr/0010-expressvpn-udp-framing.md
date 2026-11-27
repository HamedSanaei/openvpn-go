# ADR 0010 — ExpressVPN UDP framing

## Context

Two authorized ExpressVPN Manual Configuration exports use
`fragment` and `comp-lzo no` over UDP. Both servers use certificates
without a SAN and authenticate with a common-name prefix from the export.
A Community reference passed tunnel traffic with the export's fragment
and uncompressed LZO framing. Without fragment framing, control
authentication succeeded and tunnel traffic failed.

## Decision

Require explicit ExpressVPN import and a supplied CA. Verify the
certificate chain, validity, TLS server EKU, digital-signature KU and
common-name prefix before sending credentials. Require a client
certificate and key plus TLS-auth and caller-managed credentials.
The usual SAN-plus-prefix behavior continues for ordinary imports.

Place the uncompressed LZO marker inside the fragment payload. Encode
fragment headers in network byte order and authenticate each fragment
using DATA_V2. Reassemble only authenticated records with the same
local receive-key generation, first packet ID, sequence and stride. Bound a datagram to
the tunnel MTU and 32 fragments. Keep at most 32 incomplete datagrams
per session and expire them after ten seconds. Reject compressed
payloads and server attempts to enable compression. Outbound keepalives
use the same framing as IP packets. A bare keepalive received inside
authenticated DATA_V2 remains acceptable for legacy peers.

The `fragment` ceiling limits the OpenVPN UDP payload. The tunnel MTU
and UDP fragment ceiling can therefore differ. TLS exporter derivation
and allowed AEAD ciphers remain mandatory.

## Evidence

Requirements FR-006, FR-011–FR-013, FR-016, SEC-001, SEC-004, SEC-006
and SEC-009 cover peer verification, protected data channels, replay
and compression policy. The regression tests use generated PKI and a
stock OpenVPN peer. The change relies on documented wire fields and
live interoperability observations.

- [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/)
- [OpenVPN fragment wire fields](https://build.openvpn.net/doxygen/fragment_8h.html)
- [Redacted interoperability results](../EXTERNAL_INTEROP.md#expressvpn)
