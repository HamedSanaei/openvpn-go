# Xray / 3x-ui integration adapter

This directory is reserved for an optional adapter that maps the public OpenVPN Go client API to the Xray outbound lifecycle used by the target 3x-ui revision.

## Boundary rules

- The core module must not import Xray or 3x-ui packages.
- The adapter may depend on the public client, transport and tunnel APIs only.
- The adapter owns mapping of lifecycle, cancellation, packet buffers, statistics and errors to the host application's contracts.
- TUN creation and routing stay with the host application unless a separately reviewed platform adapter is introduced.
- The adapter must not weaken TLS verification, cipher policy or profile validation.
- Pin and document the exact 3x-ui/Xray revision used for integration tests.

## Planned spike

1. Inspect the target 3x-ui/Xray outbound interfaces at the time integration begins.
2. Write an adapter contract and an ADR before implementation.
3. Prove packet flow with a generated test profile and disposable OpenVPN server.
4. Prove reconnect, cancellation, shutdown and resource cleanup.
5. Measure memory, CPU and throughput overhead.
6. Keep integration tests separate from core unit tests.

No Xray dependency is included in go.mod at scaffold stage.
