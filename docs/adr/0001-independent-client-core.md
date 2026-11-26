# ADR 0001: Independent client core

- Status: Proposed
- Date: 2026-11-26

## Context

The product needs a reusable Go OpenVPN client library for embedding, with a future 3x-ui/Xray integration. The previous repository is MPL-2.0 and is not the source of implementation code for this project.

## Decision

Build a new client-only implementation from public protocol references and independently written requirements. Keep the old repository in a separate directory and Git history. Do not copy or port its source, tests, comments or documentation.

## Consequences

- More initial protocol research and test work.
- Clearer ownership and licensing path, subject to contributor/provenance review.
- Formal clean-room status remains unclaimed until a separate, unexposed implementation contributor is used.
- Server mode, TAP and legacy compression remain out of scope for v0.x.
