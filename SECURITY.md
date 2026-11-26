# Security Policy

## Project status

Automated hardening checks cover the TLS client, data channel, profile
loader, reconnect and Linux Xray adapter. The beta awaits an independent
security review of the release revision. [Hardening evidence](docs/HARDENING.md)

## Reporting a vulnerability

When private vulnerability reporting is enabled for the GitHub repository, use GitHub Security Advisories. Do not publish exploitable details in a public issue before maintainers have had a reasonable opportunity to investigate and coordinate a fix.

Until a private reporting channel is configured, do not send secrets or private VPN profiles in public issues. Open a minimal public issue asking for a secure contact channel.

## Security priorities

- Authenticate the server certificate chain and server identity by default.
- Never make insecure TLS verification the implicit fallback.
- Treat profile files and network packets as untrusted input.
- Bound packet sizes, queues, retries, parsing depth and memory use.
- Enforce replay protection on control and data channels.
- Avoid logging credentials, private keys, session keys or raw authentication payloads.
- Reject unsupported security-sensitive directives rather than silently ignoring them.
- Keep cryptographic operations in reviewed standard libraries or established cryptographic packages.
- Run race detection, fuzzing, static analysis and dependency vulnerability checks before releases.

## Disclosure

A release is not considered security-reviewed merely because its tests pass. Each release candidate must complete the security checklist in docs/SECURITY_MODEL.md and docs/TEST_STRATEGY.md.
