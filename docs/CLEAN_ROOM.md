# Independent implementation and clean-room process

## Status and limitation

On 2026-11-26 the owner chose a spec-driven independent implementation and resolved that formal clean-room separation is optional for this project. No isolated implementation appointment is required under this decision. The implementation sources are public protocol specifications and manuals, independently authored requirements and permitted test evidence. [The M0 decision record](adr/0006-m0-governance-and-scope.md) records the scope of this approval.

**Important limitation:** previous work in this ChatGPT conversation inspected and modified files in the legacy go-openvpn repository. Therefore this same already-exposed assistant/contributor cannot truthfully certify a formal legal clean-room separation. A spec-driven independent rewrite can still be developed, but a formal clean-room claim requires a separate implementation contributor who has not accessed the legacy source or its derived patches.

The project must not market itself as legally certified clean-room until this limitation is resolved and reviewed.

## Separation model

Preferred model when formal clean-room status is required:

1. Specification team: writes feature-level requirements from public OpenVPN documents, protocol references and independently observed interoperability behavior. It must not copy source code or implementation comments.
2. Implementation team: receives only the approved requirements, public protocol references, test vectors generated independently and API contracts. It must not access the legacy repository, its source files, tests, diffs, patches or implementation-specific design notes.
3. Review team: checks provenance, dependency licenses, generated files and test fixtures before release.

Describe the project as a spec-driven independent implementation. If a formal separation requirement is introduced later, record a new owner decision and appoint an isolated implementation contributor before the work governed by that requirement.

## Prohibited inputs

- Source files from the legacy go-openvpn repository.
- Its tests, fixtures, comments, README passages or internal design documents.
- Mechanical translation, renaming, refactoring or restructuring of legacy code.
- Cherry-picking or copying commits from the legacy repository.
- Reusing generated binaries or copied protocol implementation fragments.
- Copying code from another OpenVPN implementation without compatible license review.

## Permitted inputs, subject to citation and review

- Public OpenVPN wire-protocol documentation and official manuals.
- Public upstream release material and official tagged definitions for corroborating version-specific wire facts. Use independently written design, code and fixtures.
- Public standards and RFCs relevant to TLS, X.509, AEAD and network protocols.
- Independently generated test certificates and packet fixtures.
- Black-box interoperability results from a properly licensed OpenVPN installation.
- Go standard library and third-party dependencies after license/security review.

## Provenance controls

- Maintain docs/PROVENANCE.md for source references, dependencies, generated files and test fixtures.
- Every non-trivial protocol feature links to a public reference and requirement ID.
- Every dependency is listed with version, SPDX license, purpose and update policy.
- Test certificates and private keys are generated specifically for tests; never check in production credentials.
- Keep the legacy repository and this repository in separate directories and Git histories.
- Do not add the legacy repository as a Git remote to the new project.
- Do not copy old commits or preserve misleading author attribution.
- Contributors disclose relevant prior access to other implementations.

## Contributor workflow

- Require Developer Certificate of Origin (DCO) sign-off on external contributions as described in [CONTRIBUTING.md](../CONTRIBUTING.md).
- Require a provenance statement for copied/adapted snippets or generated artifacts.
- Reject contributions with unclear origin.
- Record protocol decisions in docs/adr/.
- Review license compatibility before accepting any dependency or fixture.

## Release gate

Before the first public release, an independent reviewer must verify:
- no inherited legacy source or test code is present;
- all source files have known provenance;
- dependency and generated-code licenses are compatible;
- project documentation accurately describes its independence;
- the chosen license is applied only to code the project has authority to license.

This process is engineering governance, not a legal opinion. Obtain qualified legal review if a formal clean-room or ownership guarantee is commercially important.
