# ADR 0005: MIT license selection

- Status: Accepted
- Date: 2026-11-26
- Decision owner: Hamed Sanaei

## Context

The owner wants broad adoption of the new OpenVPN Go library across Go projects and commercial products. The license should be permissive, familiar to developers and free of copyleft source-disclosure obligations.

## Decision

Use the **MIT License** for project-owned code, subject to source-provenance and ownership review.

## Rationale

- Widely recognized and familiar to open-source and commercial developers.
- Allows commercial and proprietary use, modification, redistribution and sublicensing.
- Does not require downstream users to publish their modifications.
- Requires retention of the copyright and permission notice in copies or substantial portions of the Software.
- Has no express patent grant; this is an accepted trade-off for this project.

Apache-2.0 was considered because it includes an express contributor patent grant, but its additional notice and redistribution conditions were not selected for this adoption-focused project. 0BSD and MIT-0 were also considered, but MIT's familiarity and clear attribution convention were preferred.

## Consequences

- LICENSE contains the standard MIT text.
- README and project metadata identify the SPDX license identifier as MIT.
- Dependencies and generated code still require individual license review.
- This decision does not relicense or authorize copying code from the legacy MPL-2.0 repository.
- No claim of formal clean-room legal separation is made; see CLEAN_ROOM.md.
