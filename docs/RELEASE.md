# Beta release policy

`v0.1.0-beta` covers the Go client, profile inspector and Linux Xray
adapter. Artifacts target Linux amd64 and arm64, Windows amd64 and
macOS arm64. Linux archives include `ovpn-xray`. The Go packages are
distributed as source through the versioned module.

The beta release requires the recorded M6 independent security review
and the independent license and provenance sign-off. Review the exact
revision that will be tagged. Attach the review record to the release
and resolve all critical or high findings. Test evidence and the
provenance record accompany the release candidate.
[Independent audit plan](INDEPENDENT_AUDIT_PLAN.md) · [Hardening evidence](HARDENING.md) · [Source provenance](CLEAN_ROOM.md#release-gate)

## Candidate build and publication

Build a candidate with Go pinned to `go.mod` and GNU tar.

~~~sh
bash tools/build-release.sh v0.1.0-beta linux amd64 dist
~~~

The script verifies the reviewed dependency inventory and builds with
CGO disabled, path trimming and no embedded build ID. It packages
the changelog, license notices and SPDX inventory with each archive.
The archive timestamp uses the source commit time, or
`SOURCE_DATE_EPOCH` when explicitly set. The release workflow runs the
hardening workflow and compares archives built under umasks 022 and
077. The staging tree uses mode 0755 for directories and executables
and mode 0644 for text files. Local builds for all four targets produced
identical archives under umasks 022, 077 and 002.

The release workflow attests each archive's build provenance and SPDX
SBOM. A separate job verifies both attestations against the workflow and
source commit, compares the archives' SHA-256 sums and checks that each
packaged SBOM matches the standalone copy. That job uploads
`verified-beta-candidate` and records the SHA-256 of its `SHA256SUMS`
manifest in the run summary. The manifest covers the four archives and
the standalone SBOM. The Go toolchain's patent notice ships with the
other license notices.
[Release workflow](../.github/workflows/release.yml)

## Independent approval

Dispatch the release workflow with publication disabled on the candidate
commit. Select two independent people with GitHub user accounts. Assign
one to security and the other to licenses and provenance. Configure both
as required reviewers in the `beta-release` environment. Enable **Prevent
self-review**, disable administrator bypass where GitHub supports it and
limit deployments to the release tag. Set the environment variables
`BETA_SECURITY_REVIEWER_ID` and `BETA_PROVENANCE_REVIEWER_ID` to the two
numeric GitHub user IDs. [GitHub deployment environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)

After examining the exact candidate and both attestations, each reviewer
records their respective approval on the release-gate issue using the
full commit and manifest hashes from the run summary. Use one unedited
comment per decision with one of these lines, replacing the two
placeholders. A new comment using `revoke` cancels an earlier approval
for the same candidate. [Release-gate issue](https://github.com/HamedSanaei/openvpn-go/issues/3)

~~~text
openvpn-go approve security COMMIT_SHA MANIFEST_SHA256
openvpn-go approve provenance COMMIT_SHA MANIFEST_SHA256
~~~

After both sign-offs, target the reviewed commit with the
`v0.1.0-beta` tag and dispatch with publication enabled. The publication
job checks the environment, reviewer identities, commit and manifest
against the rebuilt archives before creating the prerelease. The release
includes the SBOM, SHA-256 manifest and `RELEASE_APPROVALS.json` with the
two linked decisions.
[Approval verifier](../tools/release_approvals.py)

## Upgrades and scope

Pin an exact beta version. During the pre-1.0 series, check the changelog
for source API, directive and interoperability changes before replacing
an existing deployment. Save the working binary and profile.
Revalidate the profile, TLS identity, transport and actual packet
traffic in the destination environment. For panel deployments, test
against the exact Xray binary and recheck interface-bound routing.

The compatibility matrix lists verified configurations. The beta uses
the TLS client mode, an IP packet tunnel and negotiated AEAD.
Server mode, TAP, static-key data mode, legacy ciphers and compression
are outside its configuration policy. The beta is intended for
integration and operational evaluation.
[Compatibility matrix](COMPATIBILITY_MATRIX.md) · [Changelog](../CHANGELOG.md)
