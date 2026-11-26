# Provenance ledger

Record the origin, version, allowed use and maintainer review for every
external input used to build, specify or test the project. Retain source
references beside the affected requirement or behavior.

| Item | Origin and version | License or use | Evidence |
|---|---|---|---|
| Initial scaffold and project documents | Project-authored at commit `5b4dafc1a80198e6dca4f5eee57834ee19a4de7a` | MIT | Initial Git commit and [LICENSE](../LICENSE) |
| M0 specifications and policy | Independently authored for this project, 2026-11-26 | MIT | [M0 decision](adr/0006-m0-governance-and-scope.md) and [baseline](PROTOCOL_BASELINE.md) |
| Protocol references | OpenVPN's public wire draft, 2.6 manual and official generated protocol documentation | Technical references for wire facts | [Wire draft](https://openvpn.github.io/openvpn-rfc/openvpn-wire-protocol.html) · [Manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/) · [Protocol documentation](https://build.openvpn.net/doxygen/network_protocol.html) |
| Optional host, proxy and resource evaluation | IETF proxy standards, operating-system VPN and netlink documentation, and pinned OpenVPN Community and Core executables | Public references and locally generated lab inputs for issues #26–#34 | [Feature ledger](FEATURE_LEDGER.md) · [Optional integrations](INTEGRATIONS.md) · [Resource evidence](RESOURCE_EVIDENCE.md) |
| Connection policies | OpenVPN management and web authentication documentation, official protocol flag definitions and public X.509/PMTU/MSS standards | Protocol facts for issues #18–#25. Test inputs are project-authored. | [Policy and references](CONNECTION_POLICIES.md) · [OpenVPN 2.6.23 flag definitions](https://github.com/OpenVPN/openvpn/blob/v2.6.23/src/openvpn/ssl.h) |
| OpenVPN 2.6.23 | Official tag `v2.6.23`, commit `49620843c487a7fee58e3030b7c88681c115e24e` | External reference peer. Tagged materials corroborate protocol facts where the draft is incomplete. | [Exact release](https://github.com/OpenVPN/openvpn/releases/tag/v2.6.23) · [Compatibility matrix](COMPATIBILITY_MATRIX.md) |
| OpenVPN 2.6.22 | Signed release `v2.6.22`, commit `c9b790f5b9e8ebca5da38c22f479c31bb8d33686` | Isolated interoperability peer. Source archive SHA-256 is pinned in the build script. | [Exact release](https://github.com/OpenVPN/openvpn/releases/tag/v2.6.22) · [Build script](../tests/interop/build-peer.sh) |
| OpenVPN 2.7.9 | Signed stable release at `7b60c2aa34992639691e3a2d651fe27301e2e9d5` | External classic data and epoch negotiation reference. | [Exact release](https://github.com/OpenVPN/openvpn/releases/tag/v2.7.9) · [Signature and digest verification](../tests/interop/build-peer.sh) |
| OpenVPN 2.4.12 and 2.5.11 | Signed historical Community releases pinned in the matrix | External test peers for the default AEAD negotiation policy. | [Observations](COMPATIBILITY_MATRIX.md#candidate-coverage-for-older-servers-and-mikrotik) · [Signature and digest verification](../tests/interop/build-peer.sh) |
| OpenSSL 1.1.1w | Official source SHA-256 `cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8` | OpenSSL and original SSLeay licenses. Test-only static dependency of the 2.4.12 peer. | [Official release](https://github.com/openssl/openssl/releases/tag/OpenSSL_1_1_1w) |
| MikroTik CHR 7.25.2 | Vendor x86_64 image, SHA-256 pinned in the external test record | Proprietary VM image used as an external interoperability peer in an isolated lab. | [Image pin and results](EXTERNAL_INTEROP.md#mikrotik-routeros) |
| OpenVPN Access Server 3.2.4 | Official Linux amd64 container, digest pinned in the external test record | External self-hosted lab using a disposable local user. Raw profiles and keys stay outside the repository. | [Image pin and results](EXTERNAL_INTEROP.md#provider-and-access-server-profiles) |
| OpenVPN 3 Core 3.11.8 | Release commit `4f3bdef73245d4ee9e8216c5d65baccc9568f6ef`, source archive SHA-256 `522faf3f7485117423a9c398606062105c4453c11d4d5ebab45e7c209cc3a9ef` | AGPL-3.0-only or MPL-2.0 upstream. The upstream executable runs as an external test client. Source and binary stay in the lab, and only normalized results and binary digests appear in test evidence. | [Upstream terms](https://github.com/OpenVPN/openvpn3/blob/4f3bdef73245d4ee9e8216c5d65baccc9568f6ef/LICENSE.md) · [Build script](../tests/interop/build-openvpn3.sh) |
| Xray-core 26.10.21 | Official Linux amd64 release, commit `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74` | External interoperability peer. Its binary and assets stay outside the Go release archive. | [Exact release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.21) · [Digest and setup](../tests/interop/build-xray-peer.sh) |
| 3x-ui target | Checkout revision `e50f949a04174e26de247b40baa2e260415174e9` | Configuration boundary reference. The adapter consumes its stock Xray outbound shape. | [Integration ADR](adr/0007-xray-linux-egress.md) |
| TLS and exporter standards | RFC 5705 and RFC 8446 | Specifications for protocol behavior | [RFC 5705](https://www.rfc-editor.org/info/rfc5705) · [RFC 8446](https://www.rfc-editor.org/info/rfc8446) |
| Go and standard library | Official Go 1.26.11, Windows and Linux amd64 archives verified against published SHA-256 values | BSD-3-Clause for the Go project. Review the toolchain's bundled notices when distributing artifacts. | [Go downloads](https://go.dev/dl/) · [Go license](https://go.dev/LICENSE) |
| GitHub Actions | Checkout v4 at `11d5960a326750d5838078e36cf38b85af677262` and setup-go v5 at `40f1582b2485089dde7abd97c1529aa768e1baff` | MIT, CI tooling | [Checkout license](https://github.com/actions/checkout/blob/11d5960a326750d5838078e36cf38b85af677262/LICENSE) · [Setup-go license](https://github.com/actions/setup-go/blob/40f1582b2485089dde7abd97c1529aa768e1baff/LICENSE) |
| actionlint | `github.com/rhysd/actionlint` v1.7.11 | MIT, local M0 workflow validation tool | [Release](https://github.com/rhysd/actionlint/releases/tag/v1.7.11) · [License](https://github.com/rhysd/actionlint/blob/v1.7.11/LICENSE.txt) |
| Govulncheck | `golang.org/x/vuln` v1.10.0 | BSD-3-Clause, dependency and standard-library analysis tool | [Command and version](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck@v1.10.0) |
| GitHub artifact actions | Upload v4 at `ea165f8d65b6e75b540449e92b4886f43607fa02` and download v4 at `d3f86a106a0bac45b974a628896c90dbdf5c8093` | MIT, CI evidence and prerelease package transport | [Upload license](https://github.com/actions/upload-artifact/blob/ea165f8d65b6e75b540449e92b4886f43607fa02/LICENSE) · [Download license](https://github.com/actions/download-artifact/blob/d3f86a106a0bac45b974a628896c90dbdf5c8093/LICENSE) |
| GitHub artifact attestation | Attest v4 at `1e69f48acb82d1966a394da916b4c1698aa569d6` | MIT, release build and SPDX attestation in CI | [Attestation action license](https://github.com/actions/attest/blob/1e69f48acb82d1966a394da916b4c1698aa569d6/LICENSE) |

Protocol citations identify interoperable behavior. Keep upstream code,
expressive text, and tests out of project code and fixtures unless a
separate compatibility and rights review explicitly authorizes reuse.

## Frozen legacy reference

| Field | Value |
|---|---|
| Repository | `https://github.com/n0madic/go-openvpn.git` |
| Pinned public revision | `392ad88d39d9a2feebf9c828aa3eb0e79468c967` |
| Observation | Public upstream `master` HEAD, recorded on 2026-11-26 using `git ls-remote --symref` |
| License recorded in the initial review | MPL-2.0 |
| Disposition | Separate historical reference, excluded from specification and implementation inputs |

The original plan named a local legacy checkout at `Documents/go-openvpn`.
That directory was absent from the M0 workspace host. The pin identifies
public upstream and makes no claim about private legacy work. No legacy
source, tests, comments, fixtures or Git objects were imported. The
configured Git remote resolves to this project's own GitHub repository.
Keep the histories and workspaces separate and retain the prior-exposure
disclosure. [Source separation rules](CLEAN_ROOM.md)

## Dependency policy

M3 adds ChaCha20-Poly1305 through the maintained Go cryptography module,
because the public standard library does not expose that AEAD. The two
selected versions below were reviewed on 2026-11-26 and require no cgo.
`go mod verify` and Govulncheck 1.10.0 passed for this change.

| Module | Version | SPDX license | Scope |
|---|---|---|---|
| `golang.org/x/crypto` | v0.59.0 | BSD-3-Clause | Direct, ChaCha20-Poly1305 AEAD. [Upstream license](https://github.com/golang/crypto/blob/v0.59.0/LICENSE) |
| `golang.org/x/sys` | v0.50.0 | BSD-3-Clause | CPU detection in the core dependency graph and Linux TUN attachment in the adapter. [Upstream license](https://github.com/golang/sys/blob/v0.50.0/LICENSE) |

The beta archives carry the MIT license, Go and module notices,
available module patent terms and the SPDX inventory. The separate
reviewer verifies provenance and rights for the release revision.
[SPDX inventory](sbom.spdx.json) · [Release policy](RELEASE.md)

Review every direct addition and the transitive modules it introduces
before merging.

1. Prefer the standard library. State the requirement and why an external
   module is needed. Record the module path, exact selected version, upstream
   source, SPDX license, direct or transitive status, intended use, and any
   native or platform constraints.
2. Review maintenance activity, published vulnerabilities, transitive
   licenses and release authenticity. Record the review date and decision.
   Review updates by the same process and keep the selected versions and
   checksums in `go.mod`/`go.sum`. Record equivalent pins for generated tools
   and release images. A tool without a Go module receives its own ledger row.
3. Inspect resulting dependencies and notices during the change. Run
   `go mod verify` when dependencies are present and retain vulnerability
   scans and the SPDX SBOM at release. Revisit the pins when a relevant
   security fix is published.
4. Contributions containing generated output or third-party fragments
   record the generator/source version, input origin, license and rights
   review. Maintainers verify DCO sign-off on external commits. [Contribution process](../CONTRIBUTING.md)

## Optional userspace module

The userspace adapter needs a pure-Go TCP/IP stack with an IP packet
boundary. It uses the official gVisor Go branch, verified through Go
module checksums. Its Go 1.27.4 requirement and dependencies are
confined to the optional module. The core SPDX inventory and release
artifacts cover the core module.
[Upstream Go module](https://github.com/google/gvisor#go) · [Adapter module](../integrations/netstack/go.mod)

| Module | Version | SPDX license | Scope |
|---|---|---|---|
| `gvisor.dev/gvisor` | `v0.0.0-20261126070802-b1c44a434dad` | Apache-2.0 | Direct, userspace TCP/IP. [License](https://github.com/google/gvisor/blob/b1c44a434dada9e9eb802ab97a0d3d515b48ace5/LICENSE) |
| `github.com/google/btree` | `v1.1.2` | Apache-2.0 | Transitive. [License](https://github.com/google/btree/blob/v1.1.2/LICENSE) |
| `golang.org/x/exp` | `v0.0.0-20250711185948-6ae5c78190dc` | BSD-3-Clause | Transitive. [License](https://github.com/golang/exp/blob/6ae5c78190dc/LICENSE) |
| `golang.org/x/sys` | `v0.48.0` | BSD-3-Clause | Transitive. [License](https://github.com/golang/sys/blob/v0.48.0/LICENSE) |
| `golang.org/x/time` | `v0.15.0` | BSD-3-Clause | Transitive. [License](https://github.com/golang/time/blob/v0.15.0/LICENSE) |

Include the applicable upstream notices when distributing a binary that
embeds this adapter. Review the nested graph on dependency updates.

## Test fixture inventory

M2 generates synthetic CA and client/server certificates in
`internal/testkit/pki.go`. The interop suite uses the pinned OpenVPN CLI to
generate temporary static and wrapped client keys, including test-only
metadata, and creates its own test usernames and passwords. The SHA-256 of
the verified OpenVPN 2.6.23 source archive used for M2 was
`4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96`.
[Fixture generator](../internal/testkit/pki.go) · [Interop test suite](../tests/interop/control_test.go) · [OpenVPN signature instructions](https://openvpn.net/community-docs/sig/)

M3's vector generator uses Python standard-library HMAC and hashing for
RFC 5705 and RFC 8446 test exports, and Python Cryptography 41.0.7 for AEAD.
All secrets and payloads in the fixture are synthetic. Regenerate the MIT
fixture with `python3 internal/data/testdata/generate_vectors.py`.
[Generator](../internal/data/testdata/generate_vectors.py) · [Vectors](../internal/data/testdata/vectors.json)

M4 builds example profiles at test time from project-authored directives,
the synthetic test PKI and ephemeral keys from the pinned OpenVPN CLI.
The unit and fuzz suites also use independently constructed Static Key V1
and wrapped-key syntax fixtures. These fixtures are solely test data and
contain no deployed keys or user credentials.
[Profile parser fixtures](../profile/parse_test.go) · [Interop profiles](../tests/interop/profile_test.go)

The Core comparison reuses the project's test PKI and OpenVPN key
generation, then passes one generated profile to both clients. The UDP
probe uses a project-authored payload and runs on isolated interfaces.
[Differential lab](../tests/interop/openvpn3_test.go)

For each new fixture, record
the path, origin, generator and revision, synthetic inputs, intended
scenario, reproduction command and license or reuse terms. Use generated
keys, certificates and credentials, isolated test addresses and sanitized
traces. Keep ephemeral private material out of Git and clean it up after
the run. Independently generate crypto vectors and record how to reproduce
them without using the client's implementation as the oracle.
[Test strategy](TEST_STRATEGY.md)
