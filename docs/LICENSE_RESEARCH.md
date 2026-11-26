# License research and decision record

Status: **Decision accepted — MIT License** (2026-11-26).

## Decision

The project owner selected the MIT License to maximize adoption and reduce friction for downstream Go developers and companies.

MIT permits use, copying, modification, merging, publishing, distribution, sublicensing and sale of copies, including use in commercial and proprietary products. It does not impose a copyleft requirement to publish downstream modifications.

Redistributors must include the copyright notice and permission notice in copies or substantial portions of the Software. MIT does not contain an express patent license. Organizations that require an explicit contributor patent grant may prefer Apache-2.0, which carries additional notice and redistribution conditions.

## Alternatives considered

| SPDX ID | Attribution / notice | Express patent grant | Decision |
|---|---|---|---|
| MIT | Retain copyright and permission notice | No express grant | **Selected** |
| 0BSD | No attribution condition | No express grant | Not selected |
| MIT-0 | No attribution condition | No express grant | Not selected |
| Unlicense | Public-domain dedication; jurisdictional treatment varies | No express grant | Not selected |
| Apache-2.0 | Notice and change-related obligations | Yes | Not selected |

## Why MIT

- Widely recognized across software ecosystems.
- Familiar to Go developers and package consumers.
- Allows commercial and proprietary downstream use.
- Allows modification, redistribution and sublicensing.
- No copyleft source-disclosure obligation.
- Clear, short conditions that are easy for maintainers and downstream users to understand.

The goal of project adoption is not determined by the license alone. Interoperability, documentation, stability, release discipline, security posture and maintainer responsiveness will matter more to long-term adoption.

## Ownership and scope

A license can only be applied by someone who owns the relevant rights or has authority from all relevant rightsholders. The MIT license in this repository does not relicense the legacy MPL-2.0 repository or any code copied from it.

The new implementation must contain independently authored code and dependencies whose licenses are compatible with the project. See CLEAN_ROOM.md and PROVENANCE.md.

## Decision checklist

- [x] Owner selected MIT.
- [x] MIT license text added as LICENSE.
- [x] README identifies MIT and links to LICENSE.
- [x] License decision ADR updated.
- [x] Owner confirmed the standard MIT terms without a separate project patent grant for M0.
- [ ] Verify all initial contributors' rights and provenance before public release.
- [ ] Review dependency and generated-code licenses before adding dependencies.
- [ ] Add license scanning and SPDX/SBOM generation to release CI.
- [ ] Reconfirm copyright holder details before public release if a legal entity will own the project.

## Primary references

- MIT license text: https://opensource.org/license/mit
- OSI approved licenses: https://opensource.org/licenses
- SPDX MIT identifier: https://spdx.org/licenses/MIT.html
- Apache-2.0 patent terms: https://www.apache.org/licenses/LICENSE-2.0
