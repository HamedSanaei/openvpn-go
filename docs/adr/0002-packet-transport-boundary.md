# ADR 0002: Packet-oriented transport boundary

- Status: Proposed
- Date: 2026-11-26

## Context

OpenVPN uses packet boundaries over UDP and explicit length framing over TCP. The protocol engine should not have separate packet parsing logic for each socket type.

## Decision

Define a packet transport interface. UDP adapters expose datagrams directly; TCP adapters implement OpenVPN's 16-bit network-byte-order length prefix and expose complete protocol packets. Custom dialers and proxy adapters implement the same port.

## Consequences

- Protocol logic is transport-independent.
- TCP framing receives dedicated bounds/fuzz tests.
- The core can later support custom transport without changing protocol packages.
