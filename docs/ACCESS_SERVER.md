# OpenVPN Access Server qualification

## Scope and evidence

Authorized isolated lab: Access Server **3.2.4** (package
`3.2.4-f3c295a7-Ubuntu26`), Ubuntu 26.04 amd64, kernel 7.0.0-44-generic,
bundled OpenVPN reference 2.7.7as0. Qualification date: 2026-11-27.
This is a bounded protocol/import qualification, not full product
certification. Test-only accounts and original exports stayed on the lab
host; no private credentials, server endpoint, keys or raw profile are
included here.

The reference client verified the exported CA, server role and leaf CN
in TLS 1.3 on UDP and TCP and initialized AES-256-GCM. The Go importer
requires the exact administrator-confirmed VPN leaf common name, rather
than assuming the HTTPS name or the remote IP is the VPN identity.

## Positive matrix

Each PASS below used an authorized real AS export and verified an ICMP
request/reply through the encrypted tunnel, forced closure of the first
transport, generation 2 reconnect and a second request/reply. Except for
the explicit TLS 1.2 cap, the exports were not edited. The echo endpoint
was an isolated private Linux namespace reachable through the server's
temporary private-network NAT configuration. It was not an Internet
service. The client uses the existing packet API harness, not a host
route installer.

| Profile | Control wrapper | UDP | TCP |
|---|---|---|---|
| User-locked, cert + local password | Plain TLS | PASS | PASS |
| Auto-login, cert only | Plain TLS | PASS | PASS |
| User-locked, cert + local password | tls-auth | PASS | PASS |
| Auto-login, cert only | tls-auth | PASS | PASS |
| User-locked, cert + local password | tls-crypt | PASS | PASS |
| Auto-login, cert only | tls-crypt | PASS | PASS |
| User-locked, cert + local password | tls-crypt-v2 | PASS | PASS |
| Auto-login, cert only | tls-crypt-v2 | PASS | PASS |
| Server-locked v2, local password only | tls-crypt-v2 | PASS | PASS |

All 18 cases negotiated TLS 1.3, AES-256-GCM, TLS exporter derivation
and classic DATA_V2. The v2 certificate-bearing rows were also repeated
with the server explicitly configured for tls-crypt-v2 (4 additional
successful executions). For server-locked v2, temporarily enabling
certificate-less VPN connections and exporting a new generic profile
was necessary; the explicit client password-only policy was used.

| Focused user-locked / tls-crypt variant | UDP | TCP |
|---|---|---|
| TLS 1.3 / AES-128-GCM | PASS | PASS |
| TLS 1.3 / CHACHA20-POLY1305 | PASS | PASS |
| TLS 1.2 / AES-256-GCM (explicit client max 1.2) | PASS | PASS |

The server cipher list was restricted to the named AEAD for each cipher
variant. These are 24 distinct positive traffic/reconnect cases (28
successful executions including repeated v2 rows), not a full Cartesian
product of all server settings. The client did not negotiate CBC.

## Negative and lifecycle evidence

- Incorrect exact VPN server identity: rejected at TLS verification
  with `connect:certificate_verification_failure`; no traffic.
- Incorrect local password: rejected with
  `connect:authentication_failure`; no traffic.
- Strict import rejects the legacy CBC hint. Opt-in import accepts it
  only as a warning; explicit CBC data offers and fallback are rejected.
- Synthetic regression tests cover conflicting trust policy, missing
  server role, malformed and duplicate client-cert markers, timer limits,
  push validation and bidirectional IPv6 blocking without consuming a
  packet ID. They use generated test certificates.
- Forced user-locked/tls-crypt UDP rekey with a 5-second interval:
  two rekeys and three verified echoes in generation 1. A third attempt
  was canceled by test shutdown, not counted.
- The equivalent accelerated TCP rekey installed key 1 but did not
  verify an echo afterward; key 2 reset failed and a reconnect began.
  **TCP rekey is not qualified by this run.** Normal TCP reconnect
  passed in the positive matrix. Investigate reference parity before
  changing protocol logic.

Initial UDP probes aimed at the server-assigned VPN gateway failed
to receive ICMP with DCO both enabled and disabled. The bundled
reference client in a separate namespace also initialized but received
no gateway echo (0/3). The private-destination test resolved the
measurement ambiguity, rather than changing UDP protocol logic.
The final traffic matrix does not claim to qualify all DCO settings
or to prove host routing/IPv6 leak protection.

## Reproduction

Use a disposable, administrator-authorized AS installation. Keep
the generated profiles and password files in a private directory
outside the repo (0600 files). Generate user-locked and auto-login
profiles using the server's supported CLI or UI. Change the wrapper
and cipher settings on the lab only; create fresh exports where
needed. Restore each previous setting after testing. The official
documentation describes [profile types](https://openvpn.net/as-docs/v3/connection-profiles/),
[control protection](https://openvpn.net/as-docs/v3/tutorials/tutorial--change-tls-control-channel-security/),
[ciphers](https://openvpn.net/as-docs/v3/tutorials/tutorial--change-encryption-cipher/)
and [certificate-less profiles](https://openvpn.net/as-docs/v3/tutorials/tutorial--connecting-without-certificate/).

Build a Linux test binary and run it on an authorized lab client
with a test-owned private echo destination:

```sh
CGO_ENABLED=0 go test -c -o /tmp/ovpn-interop.test ./tests/interop
export OVPN_EXTERNAL_ACCESS_SERVER_NAME='administrator-confirmed exact CN'
export OVPN_EXTERNAL_PROFILE=/private/lab/user-locked.ovpn
export OVPN_EXTERNAL_AUTH_FILE=/private/lab/auth
export OVPN_EXTERNAL_REMOTE=1
export OVPN_EXTERNAL_ECHO=10.254.253.2
export OVPN_EXTERNAL_EXPECT=verified
/tmp/ovpn-interop.test -test.run '^TestExternalProfile$' -test.v -test.count=1
```

Select a remote index matching the intended transport. Omit the auth
file for auto-login. For the modern certificate-less export explicitly
set `OVPN_EXTERNAL_PASSWORD_ONLY=1`; `setenv CLIENT_CERT 0` alone cannot
grant permission. For focused rekey tests use
`OVPN_EXTERNAL_REKEY=1`, `OVPN_EXTERNAL_REKEY_SECONDS=5`,
`OVPN_EXTERNAL_REKEY_COUNT=2`, and
`OVPN_EXTERNAL_EXPECT=rekey_verified`. Clean up only the disposable
test account between runs; the unlicensed server's two simultaneous
connections can otherwise confound authentication results.

Inspect a trusted export with `ovpn-inspect -access-server-name "exact CN"`;
add `-allow-password-only` for the modern server-locked v2 profile.
Pass a credential file or caller-managed credentials as required.

## Remaining qualification

PAM, LDAP, RADIUS, SAML/web authentication, real MFA/TOTP, external PKI,
profile download tokens/API, older server-locked pseudo-profiles, dynamic
control wrapping, epoch data, IPv6 traffic, full/split host routing,
DNS leak protection, failover across AS nodes, and the full cross-product
of supported settings are not qualified here. CBC, compression, TAP,
static-key and unencrypted data modes remain outside the secure client
policy. Do not interpret this record as support for every Access Server
feature. Issue #17 remains open for other provider and AS qualification.

## Additional DNS and public-chain TLS qualification

Follow-up lab, 2026-11-27: the supplied publicly trusted wildcard
certificate covers both administrator-provided DNS names. Fresh
user-locked exports using the IPv4-resolving DNS name passed TCP and
UDP data/reconnect (two cases). The VPN server identity remains the
administrator-confirmed exact CN and the profile CA.

Four more cases passed with the real public certificate and its full
chain: two DNS identities, each over IPv4 and IPv6 loopback to an
ephemeral HTTPS CONNECT fixture, forwarding exclusively to the IPv4
Access Server TCP endpoint. Both VPN generations passed private
IPv4 echo. Each corresponding wrong TLS name was rejected before
forwarding any CONNECT to the VPN endpoint. The proxy uses system
roots; the inner VPN separately uses its original CA and server
identity. No production web TLS setting or VPN PKI was replaced.
The key was used in place on the authorized lab and never committed.

| Additional case | Result |
|---|---|
| DNS-hostname export, TCP and UDP | 2/2 verified |
| Public TLS proxy certificate, two names x two loopback families | 4/4 verified |
| Incorrect TLS proxy name | 4/4 rejected before forwarding |
| Direct IPv6 Access Server transport | Not supported by AS 3.x according to the vendor |
| Inner IPv6 live data | Not qualified: temporary AS IPv6 pool configuration failed at server restart and was restored |

The vendor distinguishes [web TLS from VPN certificates](https://openvpn.net/as-docs/v3/tutorials/tutorial--lets-encrypt-ssl-certificate-access-server/)
and [IPv6 transport from tunnel IPv6](https://openvpn.net/as-docs/v3/ipv6-support/).
IPv6 loopback to the proxy is not evidence of direct IPv6 transport
to Access Server or public IPv6 reachability. The additional ICMPv6
probe accepts an explicit test-owned IPv6 echo destination and
checks source/destination, pseudo-header checksum and random nonce.
The synthetic regression covers the probe and the blocked IPv6
policy; real Access Server inner IPv6 remains unqualified.

Run the optional TLS proxy fixture on the authorized lab with the
existing external-profile variables, selecting its TCP remote and
a private IPv4 echo target. Set the following additional variables
to local paths and the intended verified names (never put a key
in the repository). The fixed target must match the resolved VPN
TCP destination and the fixture binds only to loopback.

```sh
export OVPN_EXTERNAL_TLS_CERT=/private/lab/fullchain.pem
export OVPN_EXTERNAL_TLS_KEY=/private/lab/privkey.pem
export OVPN_EXTERNAL_TLS_NAME=administrator-confirmed.example
export OVPN_EXTERNAL_TLS_TARGET=192.0.2.10:443
/tmp/ovpn-interop.test -test.run '^TestExternalTLSProxyProfile$' -test.v -test.count=1
```

There are now 30 distinct verified positive scenarios across the
initial matrix and these focused DNS/proxy tests (34 successful
executions including the earlier repeated v2 cases); these are
not a full Cartesian product or all product features.
