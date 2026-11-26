# Protocol feature and provenance ledger

Observations are scoped to the pinned references and named tests.
Community 2.6.23 remains the primary server baseline. OpenVPN 3 Core
3.11.8 is an independent executable in the differential and performance
labs. The project implements protocol behavior from public specifications
and independently authored fixtures. [Provenance ledger](PROVENANCE.md) · [Review boundaries](CLEAN_ROOM.md)

| Feature | Public reference and version | Observed behavior | Local status and test |
|---|---|---|---|
| TLS 1.2 and 1.3, key method 2, exporter, DATA_V2 | [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [Wire draft](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html) | 2.6.22 and 2.6.23 validate the classic AEAD path over TCP and UDP. Core 3.11.8 matches the generated differential cases. | Supported. `TestControlOpenVPN26`, `TestDataOpenVPN26`, `TestOpenVPN3Differential`. |
| tls-auth, tls-crypt and tls-crypt-v2 cookies | [Community 2.6.23 release](https://github.com/OpenVPN/openvpn/releases/tag/v2.6.23) · [Wire draft](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html) | Pinned Community fixture accepts the documented protection modes and forced cookies. | Supported in the two transports. `TestControlOpenVPN26`, `TestDataOpenVPN26`. |
| Certificate pins, CRLs, external signing | [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | A 2.6.23 peer with synthetic credentials verifies after pin rotation. A revoked or wrongly named peer is rejected. | Additive trust policy, verified issuer CRLs, caller-owned signer. `TestServerTrustAndExternalIdentity`, `TestCRLChecksVerifiedChain`. |
| Pending auth and token refresh | [OpenVPN management notes](https://github.com/OpenVPN/openvpn/blob/v2.6.23/doc/management-notes.txt) · [Web authentication draft](https://github.com/OpenVPN/openvpn-rfc/blob/master/webauth.md) | Community 2.6.23 exchanges text challenges, rejects expired tokens and accepts a new login. Web handoff uses mock callbacks. | CR_TEXT, verified token updates and opt-in HTTPS handoff. `TestDeferredTextAuthentication`, `TestExpiredTokenAndReauthentication`, `TestBrowserCallback`. |
| UDP notification, MTU and repeated rekey | [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [Wire draft](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html) | 2.6.23 observes EXIT followed by server cleanup. Large IP datagrams obey the active effective MTU. | Supported modern negotiated variants. `TestNegotiatedUDPExit`, `TestTunnelPacketMTU`, `TestLossySessionSoak`. |
| TCP proxies | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#name-connect) · [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) · [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) | Local controlled proxies verify CONNECT and SOCKS5 framing, credentials, and refusal handling. | Opt-in adapter. `TestProxyTCPAdapters`, `TestProxyFailureAndCancellationAreRedacted`. |
| Community 2.7 epoch negotiation | [Community 2.7.9](https://github.com/OpenVPN/openvpn/releases/tag/v2.7.9) · [Wire draft](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html) | Community negotiates epoch between compatible peers. Its classic path is independently exercised against Go. | Classic path supported. Unadvertised epoch is rejected. `TestCommunity27EpochPolicy`. |
| Historical 2.4.12 and 2.5.11 peers | [Community release support](https://community.openvpn.net/Pages/Supported%20versions) · [2.6 transition notes](https://github.com/OpenVPN/openvpn/blob/v2.6.23/Changes.rst) | The tested older peers omit the exporter and may omit cipher negotiation. | Deliberately fail closed. `TestLegacyCommunityAEADPolicy`. |
| RouterOS CHR 7.25.2 and Access Server 3.2.4 | [RouterOS OpenVPN documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/2031655/OpenVPN) · [Access Server client profiles](https://openvpn.net/as-docs/v3/using-the-client-web-ui/) | Controlled profiles documented negotiation or parser incompatibilities. Provider and hardware support requires separate evidence. | No compatibility claim. `TestExternalProfile` and [recorded evidence](EXTERNAL_INTEROP.md). |
| Linux offload | [Linux ovpn netlink ABI](https://docs.kernel.org/netlink/specs/ovpn.html) · [Community 2.7.9 DCO](https://github.com/OpenVPN/openvpn/blob/v2.7.9/README.dco.md) | The comparison uses userspace exclusively and records no kernel measurements. | Evaluated in [ADR 0008](adr/0008-linux-data-offload.md). `TestComparativeBenchmark` tags userspace in its output. |

Server operation, TAP, insecure data ciphers, compression, legacy
key derivation, native platform packaging and implicit downgrade
remain outside the supported core. Use the separate compatibility
matrix for mode and platform detail. [Compatibility matrix](COMPATIBILITY_MATRIX.md)

## Review cadence

Review the upstream releases and security advisories monthly and before
each release. The monthly workflow saves public release and advisory
metadata as a review artifact. The maintainer compares it against the
exact references in this ledger and the release inventory, records any
impact and resulting tests, and keeps past observations tied to their
original versions. Update a pin only after reviewing the release
integrity and license terms and rerunning relevant independent
tests. Handle public security updates through the existing disclosure
and release process. [Upstream review workflow](../.github/workflows/upstream-review.yml) · [OpenVPN security advisories](https://openvpn.net/security-advisories/) · [Release approval policy](RELEASE.md)
