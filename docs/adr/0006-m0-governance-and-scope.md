# ADR 0006 — M0 governance and scope

| Record | Value |
|---|---|
| Status | Accepted |
| Decision date | 2026-11-26 |
| Decision owner | Hamed Sanaei |
| Project | OpenVPN Go, repository `HamedSanaei/openvpn-go`, module `github.com/hamedsanaei/openvpn-go` |

The owner confirmed the OpenVPN 2.6 scope, the standard MIT license with no express patent grant, and spec-driven independent development with no requirement for formal clean-room separation. The repository and module name follow the configured Git origin and existing Go module declaration. The current `LICENSE` identifies Hamed Sanaei as the copyright holder. The release review will verify contributor rights and any change in the owning entity. [MIT decision](0005-license-selection.md) · [Source separation](../CLEAN_ROOM.md)

The release scope covers an embeddable TLS-mode client using UDP or TCP, a caller-supplied IP packet tunnel and the authentication, control protection and data modes declared in the compatibility matrix. Version 2.6.23 is the exact initial reference peer selected within the approved 2.6 scope. The 3x-ui/Xray adapter remains M7 work. [Product requirements](../REQUIREMENTS.md) · [Compatibility matrix](../COMPATIBILITY_MATRIX.md)

The legacy reference is pinned by Git object ID in the provenance ledger. M0 used repository identifiers only. The separate local legacy checkout named in the original plan was unavailable, so the frozen identifier comes from public upstream Git metadata. Future contributions require a provenance review, and external contributions require DCO sign-off. [Provenance ledger](../PROVENANCE.md) · [Contribution process](../../CONTRIBUTING.md)
