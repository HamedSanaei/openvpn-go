# OpenVPN connection policies

## Server trust and client identity

`TLSConfig.ServerFingerprints` accepts one or more SHA-256 fingerprints
of the complete DER leaf certificate. Configure both certificates' pins
before rotating a certificate. The configured CA or explicitly enabled
system roots, endpoint identity, validity period and TLS server purpose
still apply. A matching pin cannot override any other trust check.

`TLSConfig.CRL` accepts a PEM bundle of complete X.509 CRLs. At least
one verified chain must have a current, correctly signed list for every
non-root certificate's issuer. Refresh the bundle before its earliest
applicable `nextUpdate`. Missing, stale, wrong-issuer and invalidly
signed lists fail closed. A listed serial invalidates that chain. One
list per issuer name is allowed. Delta, indirect and
distribution-point-scoped CRLs, directory mode and network fetching
are outside this policy. Provision an updated client configuration to
replace CRLs. [OpenVPN 2.6 TLS options](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)

An application can set `TLSConfig.Signer` for a fixed hardware or
software key or `TLSConfig.KeyProvider` to unlock a key on demand. Set
`Certificate` to the matching PEM chain and omit `PrivateKey`. The same
choice is available through `profile.Options.Identity` with a `cert`
directive. The provider runs in the handshake context after server
verification and when the peer requests a client certificate. Return a
signer compatible with the peer's signature algorithms. Callbacks must
honor their context. A signer may additionally implement
`SignContext(context.Context, io.Reader, []byte, crypto.SignerOpts)`
returning `([]byte, error)` to propagate cancellation into a token or
hardware request. An implementation of the ordinary `Sign` method must
enforce its own I/O bounds. Key provider failures and signer failures
surface as redacted authentication errors.

| Container | Assessment |
|---|---|
| PKCS#12 | SSLMate go-pkcs12 is BSD-3-Clause and has a `DecodeChain` API. It can read legacy as well as modern containers, so a provider must require an approved cipher, KDF and integrity policy. The package has a published password verification advisory. Select a patched release and verify resource limits before integrating it. [Upstream](https://github.com/SSLMate/go-pkcs12) · [Advisory](https://github.com/advisories/GHSA-mpwr-8vm7-h73f) |
| Encrypted PKCS#8 PEM | youmark/pkcs8 is MIT and supports PBES2. A provider must enforce permitted KDFs, work factors, IV and ciphertext limits and compatible key types. Go's `x509.ParsePKCS8PrivateKey` accepts unencrypted DER. [Upstream](https://github.com/youmark/pkcs8) · [Go documentation](https://pkg.go.dev/crypto/x509#ParsePKCS8PrivateKey) |
| Traditional encrypted PEM | Go deprecates RFC 1423 PEM decryption because the format lacks authenticated encryption. Convert old keys in a trusted provisioning environment before use. [Go documentation](https://pkg.go.dev/crypto/x509#DecryptPEMBlock) |

Applications own decryption, passphrase input and key storage behind
the provider interface. The profile parser accepts unencrypted PEM keys
and leaves encrypted containers unsupported. The core adds no container
dependencies.

## Interactive authentication and federation

`client.Config.Authentication.Credentials` obtains fresh credentials
over a verified TLS connection when the session has no server token.
It is exclusive with static credentials. Initial setup supports documented
`AUTH_PENDING` timeouts and `INFO_PRE,CR_TEXT` prompts. The configured
handshake deadline also bounds interaction by default. A nonzero
`Authentication.PendingTimeout` gives one verified `AUTH_PENDING`
message a separate budget capped by the server's request, the configured
duration and the connection caller's deadline. The cap is five minutes.
`Authentication.AllowPassivePending` permits waiting for the authenticated
server's decision without registering local UI callbacks. A challenge or
web handoff still requires its corresponding callback. The client
accepts up to four text prompts per handshake and sends bounded, base64-encoded
`CR_RESPONSE` replies. The application owns user interaction and must
honor cancellation. Treat prompt and URL text as sensitive peer input.

A server-issued `auth-token` and an optional token username are scoped
to the session. A username from the initial push is held as token
metadata until a token is installed. It does not change the username or
password sent for ordinary credentials. Live refreshes must include a
token. The installed token takes precedence on rekey. The client treats
every `AUTH_FAILED`, including an expired token reported as `AUTH_FAILED,SESSION:`, as
terminal for that operation. An explicit new connection reacquires
credentials from the callback. Peer text and callback errors are
omitted from diagnostics, events and logs. [Wire draft](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#name-control-channel-messages) · [OpenVPN management protocol](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt)

Set `Authentication.WebAuth` to opt into one HTTPS `WEB_AUTH` handoff
during pending authentication. The core waits for the verified VPN
server's result. It never opens a browser or exchanges SAML assertions.
`integrations/webauth.New` supports applications with a provider that
can round-trip application-generated state to a registered HTTPS
callback. It compares the login and callback HTTPS authorities with
the default port normalized, matches the exact escaped callback path
and verifies one-use state within the interaction deadline. Applications supply the
browser and listener, and own navigation and redirect policy.

The integration is tested with a mock provider. Provider-specific
profiles, AWS's CRV1 SAML flow, deferred rekey prompts, proprietary
loopback endpoints, implicit token extraction, deprecated `OPEN_URL` and
`WEB_AUTH` proxy or hidden webview modes remain unsupported. Evaluate
provider-specific protocols with a mock IdP or an authorized lab.
[OpenVPN web authentication](https://github.com/OpenVPN/openvpn-rfc/blob/master/webauth.md) · [OpenVPN 3 Core](https://openvpn.github.io/openvpn3/)

## Resolution and shutdown

A verification failure while opening a TLS proxy connection is a
terminal certificate error reported at the dial stage. A retry budget,
including unlimited retry, does not authorize trying another VPN
endpoint through an untrusted proxy.

The default socket dialer delegates DNS to Go. A custom
`client.Resolver` supplies ordered addresses per attempt. The client
filters by `tcp4`/`udp4`, `tcp6`/`udp6` or source address family
and excludes unspecified and multicast destinations. Literal remotes
use this same destination policy. Delegated DNS and proxy resolution
keep their transport-specific policy. The client
deduplicates and considers up to 16 addresses. Socket errors try later
addresses within the same dial deadline. A retryable OpenVPN handshake
failure advances past the selected TCP or UDP candidate on the next
visit to that endpoint.
A resolver lookup never changes the configured TLS server name or the
reported endpoint. `ResolveRetry` bounds retries within the dial deadline
and `ResolveUntilDialDeadline` uses the whole deadline. Local address and
port binding use the built-in dialer. Supplying local bind settings with
a custom dialer is a configuration error. Native sockets use the actual
connected IP family in OpenVPN's option consistency record. A custom
transport can expose its VPN peer through `PeerIP() netip.Addr`.
Proxy streams leave the actual VPN address unspecified.

`Client.Close` sends a single TLS-protected `EXIT` when the UDP client
opts in and the authenticated push negotiates `cc-exit`. The reliable
acknowledgment wait is bounded to 250 ms. A dead peer or a concurrent
rekey still permits cleanup. Cancellation of `Connect` and `Run` retains
its existing immediate teardown path. [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [Control protocol flags](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html#name-protocol-flags)

## Inner packet size and MSS

The effective inner ceiling is the smallest configured `TunnelMTU`,
accepted authenticated `tun-mtu` and transport packet limit minus the
24-byte DATA_V2 AEAD overhead. A configured IPv6 tunnel requires a
ceiling of at least 1280. `ControlInfo.Tunnel.MTU` reports the effective
value when a local or peer tunnel MTU was specified.
`ControlInfo.MaxTunnelPacketSize` also reports the ceiling when only the
wire limit applies. Packets above the configured inner MTU are dropped
by forwarding. Oversized inbound ciphertext is still
subject to the hard transport limit. The data channel authenticates
received packets before treating any packet as IP traffic or considering
it for liveness. Inbound packets over the inner limit are discarded.

The adapter host provisions its TUN MTU and handles path MTU
discovery, ICMP and fragmentation. For UDP over a path without outer
fragmentation, start with the path MTU minus 52 bytes for IPv4 or 72 bytes
for IPv6 (outer IP, UDP and DATA_V2 headers with no IP extensions).
For example, an outer MTU of 1500 yields an inner ceiling of 1448 or
1428 bytes. TCP transport adds a two-byte frame length and uses the
outer TCP stack's segmentation and PMTU handling.

`xray.Options.MSSMTU` or `ovpn-xray -mss-mtu` optionally lowers existing
TCP MSS options on complete IPv4 and IPv6 SYN and SYN-ACK packets in
both directions. The adapter uses the lower of that ceiling and the
generation's known MTU and updates the TCP checksum. Fragments and TCP
authentication options are left intact. [RFC 1191](https://www.rfc-editor.org/rfc/rfc1191) · [RFC 8201](https://www.rfc-editor.org/rfc/rfc8201) · [RFC 6691](https://www.rfc-editor.org/rfc/rfc6691)
