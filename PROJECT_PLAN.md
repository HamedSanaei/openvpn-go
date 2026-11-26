# OpenVPN Go — Project Plan

This is the working entry point for the new independent OpenVPN client library.

**Status:** scaffold and planning documents created; no protocol implementation yet.  
**Local path:** C:\Users\Hamed\Documents\openvpn-go  
**Proposed module:** github.com/hamedsanaei/openvpn-go (provisional)  
**License:** MIT (selected; see LICENSE and docs/LICENSE_RESEARCH.md).  
**SPDX-License-Identifier:** MIT

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

## First milestone

Start with M0 only. Before implementation:
- confirm the copyright holder details for public release;
- resolve whether formal clean-room separation is required;
- approve protocol compatibility targets;
- review requirements and acceptance tests;
- install and pin the Go toolchain and verify CI.

The existing legacy repository at Documents\go-openvpn remains untouched by this new scaffold and must not be used as a source for implementation code.
