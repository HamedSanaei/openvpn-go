# Provenance ledger

This ledger records the origin of implementation inputs. Update it for every new dependency, generated file, protocol fixture or externally sourced code fragment.

## Initial scaffold

| Item | Origin | License/status | Notes |
|---|---|---|---|
| Project plan and requirements | Independently authored for this project | MIT selected | Based on user requirements and public protocol references |
| Architecture and package skeleton | Independently designed | MIT selected | No protocol implementation copied |
| Protocol baseline | Public OpenVPN documentation | Reference material; not copied as source code | URLs recorded in PROTOCOL_BASELINE.md |
| Go module and CI scaffold | Independently authored | MIT selected | No third-party source code included |

## Legacy repository boundary

- Legacy repository: https://github.com/n0madic/go-openvpn
- Legacy license observed in prior review: MPL-2.0.
- No source files, tests, comments, documentation or commits from that repository are included in this scaffold.
- Previous ChatGPT work has inspected and modified the legacy source. This is disclosed in CLEAN_ROOM.md; formal clean-room status is not claimed.
- The MIT license in this repository does not relicense the legacy repository or authorize copying its code.

## Dependency inventory

No third-party Go dependencies have been added to go.mod at scaffold stage.

For each future dependency, record:
- module path and pinned version;
- purpose and whether it is direct or transitive;
- SPDX license identifier and source URL;
- maintenance/security review date;
- whether it introduces cgo, native binaries or platform constraints.

## Test fixture inventory

No production profile, credential, certificate or traffic capture is included. Test keys/certificates must be generated specifically for this repository and listed here.

## Update rule

A pull request that adds external code, generated code, a fixture or a dependency must update this file and pass the license/provenance review.
