# OpenVPN Go — Project Plan

This is the working entry point for the new independent OpenVPN client library.

- **Status** · M3 complete. M4 is the next implementation milestone.
- **Module** · `github.com/hamedsanaei/openvpn-go`
- **License** · [MIT](LICENSE)
- **SPDX-License-Identifier** · MIT

## Read in this order

1. docs/PROJECT_PLAN.md — product goals, scope and release definition.
2. docs/REQUIREMENTS.md — functional and security requirements with IDs.
3. docs/ARCHITECTURE.md — modular package boundaries and data flow.
4. docs/CLEAN_ROOM.md — source restrictions and clean-room limitation.
5. docs/PROTOCOL_BASELINE.md — public protocol facts and source references.
6. docs/SECURITY_MODEL.md — threat model and security gates.
7. docs/TEST_STRATEGY.md — unit, fuzz, interoperability and release tests.
8. docs/MILESTONES.md — delivery sequence and exit gates.
9. docs/TASKS.md — implementation task register.
10. docs/LICENSE_RESEARCH.md — license comparison and accepted MIT decision.
11. docs/PROVENANCE.md — source/dependency/test-fixture ledger.

## M0 handoff

The owner approved the scope, MIT patent policy and independent development
process. The initial reference peer is OpenVPN Community 2.6.23. The
specification and acceptance plans are in [docs/PROTOCOL_BASELINE.md](docs/PROTOCOL_BASELINE.md)
and [docs/TEST_STRATEGY.md](docs/TEST_STRATEGY.md). The
[M0 gate](docs/MILESTONES.md#m0--governance-requirements-and-protocol-specification)
records the engineering evidence and the source reference is frozen in the
[provenance ledger](docs/PROVENANCE.md). The [M1 exit checks](docs/MILESTONES.md#m1--foundation-and-public-api) record
the implemented foundation. The [M2 exit checks](docs/MILESTONES.md#m2--control-channel-and-tls) record
control interoperability. The [M3 exit checks](docs/MILESTONES.md#m3--data-channel-and-cryptography) record
tunnel traffic and rekey. Continue with [M4](docs/TASKS.md#m4--profile-parser).
