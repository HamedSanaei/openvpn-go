# ADR 0004: Cryptographic primitive policy

- Status: Proposed
- Date: 2026-11-26

## Context

The project implements a security-sensitive VPN protocol. General cryptographic primitives are difficult to implement correctly and must not be handwritten.

## Decision

Use Go standard-library cryptography where available and established maintained packages where required. Implement only protocol-specific key derivation, packet formatting, nonce construction and state management from public specifications. Maintain an explicit cipher allow-list and test vectors.

## Consequences

- Dependencies must be reviewed and pinned.
- Every supported data cipher needs independent test vectors and real-server interoperability tests.
- No implicit downgrade or insecure TLS verification fallback is allowed.
