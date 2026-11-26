# Contributing

This project is being developed as an independent implementation from public protocol material.

## Before contributing

1. Read docs/CLEAN_ROOM.md and docs/SECURITY_MODEL.md.
2. Open or update a requirement/task before implementing a protocol feature.
3. Record the public specification or standard that supports protocol behavior.
4. Check dependency licenses and add new dependencies only with a documented reason.
5. Never submit credentials, private VPN profiles, private keys or real user traffic captures.

## Clean-room and provenance rules

- Do not copy, translate, mechanically port or adapt source code, tests, comments, documentation or fixtures from the legacy go-openvpn repository.
- Implement against public protocol documentation and independently authored requirements.
- Record the origin of every third-party dependency and test fixture.
- If a contribution is based on another implementation, disclose it before submission; do not silently incorporate its code.
- Do not claim formal legal clean-room status until the project has completed the separation and provenance review described in docs/CLEAN_ROOM.md.

## Change process

- Keep changes focused and explain protocol/security implications.
- Add unit tests for parsing, framing, state transitions and error paths.
- Add fuzz targets for untrusted packet and profile input.
- Add interoperability tests for changes that affect the wire protocol.
- Run gofmt, go test ./..., go test -race ./... and go vet ./....
- Update docs/REQUIREMENTS.md and docs/TASKS.md when behavior or scope changes.

## Contribution certification

The project plans to use the Developer Certificate of Origin (DCO) sign-off model. Once enabled, contributors must use git commit --signoff and certify that they have the right to submit the work under the project license selected by the owner.

The final license and contribution policy must be approved before accepting external code contributions.
