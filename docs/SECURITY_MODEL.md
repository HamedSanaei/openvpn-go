# Security model and threat boundaries

## Assets

- User credentials and authentication tokens.
- Client private keys and CA material.
- TLS session secrets and data-channel keys.
- Tunnel plaintext IP packets.
- Session identity, replay counters and endpoint metadata.
- Availability and integrity of the VPN connection.

## Threats in scope

- Active network attacker modifying, replaying, truncating or injecting packets.
- Rogue server presenting an invalid, expired or wrong-name certificate.
- Malformed OVPN profiles and malicious inline credential blocks.
- Malformed, oversized or adversarial network packets.
- Duplicate, stale or reordered control/data packets.
- Endpoint failover accidentally weakening certificate verification.
- Resource exhaustion through packet floods, retransmission storms, oversized frames or unbounded queues.
- Credential/key disclosure through logs, errors, crash output or test artifacts.
- Race conditions during reconnect, rekey and shutdown.

## Trust boundaries

1. Profile input: untrusted file and referenced external files.
2. Network transport: fully untrusted bytes.
3. TLS peer: untrusted until chain and identity verification succeeds.
4. Tunnel input: caller-owned packet data; validate size and ownership.
5. Integration adapter: separate application boundary; must not bypass core verification.
6. Dependencies: trusted only after version, license and security review.

## Mandatory controls

- Verify certificate chain and server identity by default.
- Require an explicit, named opt-in for any chain-only or non-standard verification mode; never make it the default.
- Clone TLS configuration per endpoint; never allow failover to silently change the identity being verified.
- Use constant-time comparisons where secrets or authentication tags are compared.
- Use standard/maintained cryptographic primitives; do not implement AES, ChaCha20, Poly1305, HMAC or TLS primitives from scratch.
- Implement protocol-specific key derivation, nonce construction and packet formatting only from documented protocol rules with independent test vectors.
- Enforce replay protection and strict packet/state validation.
- Bound packet length, profile size, parser nesting, control queues, retransmit queues, retries and goroutine lifetimes.
- Reject compression and weak legacy ciphers by default.
- Never execute scripts or shell commands from a profile.
- Never log credentials, private keys, session keys, auth payloads or decrypted packet content.
- Make error messages useful without including secrets or raw private configuration.
- Ensure context cancellation and Close unblock every read/write and stop all timers/goroutines.

## Cryptographic policy

- Prefer Go standard library crypto/tls, crypto/cipher, crypto/rand and crypto/x509.
- Use a maintained Go cryptography package only when the standard library lacks a required primitive.
- Maintain an allow-list for negotiated data ciphers.
- Document the exact key derivation, nonce construction, authentication tag length and replay policy for each supported data format.
- Do not silently downgrade when negotiation fails.
- TLS minimum version and cipher policy must be reviewed against interoperability requirements; do not hard-code a policy that breaks supported OpenVPN deployments without a clear error.

## Security acceptance gates

- Certificate-chain and hostname mismatch tests.
- Expired/not-yet-valid certificate tests.
- Wrong CA and missing certificate tests.
- Endpoint-specific SNI and failover identity tests.
- Packet truncation, length overflow and malformed opcode tests.
- Control/data replay and duplicate packet tests.
- Key-ID rollover and rekey transition tests.
- Secret-redaction tests.
- Fuzzing of parser, framing and packet decoders.
- Race detector and goroutine-leak checks.
- Dependency vulnerability and license scan before release.

## Known limitations

This document is a threat-model baseline, not a security audit. The project must not claim production security until the implementation exists, interoperability is demonstrated and an independent security review has been completed.
