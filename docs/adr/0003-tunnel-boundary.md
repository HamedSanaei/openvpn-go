# ADR 0003: External packet tunnel boundary

- Status: Proposed
- Date: 2026-11-26

## Context

The library is intended for 3x-ui/Xray integration and other embedding applications. TUN device creation and host routing are platform/application concerns.

## Decision

The core exchanges IP packets through a packet-oriented interface supplied by the caller. OS TUN devices and Xray adapters remain separate packages or applications. The protocol core does not modify routes or firewall state.

## Consequences

- Easier unit and integration testing.
- No privileged OS operations in the core.
- The adapter must define ownership, cancellation and packet buffer semantics explicitly.
