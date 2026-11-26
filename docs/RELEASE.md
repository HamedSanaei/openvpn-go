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
[Hardening evidence](HARDENING.md) · [Source provenance](CLEAN_ROOM.md#release-gate)

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
hardening workflow and builds each archive twice to compare the bytes.
Local candidate builds for all four targets produced identical archives
on repetition and passed SHA-256 verification.

For public publication, configure the `beta-release` environment with
required reviewers, then dispatch the workflow on the reviewed
`v0.1.0-beta` tag with publication enabled. The publication job verifies
the tag and emits archive SHA-256 sums with a GitHub prerelease.
[Release workflow](../.github/workflows/release.yml)

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
