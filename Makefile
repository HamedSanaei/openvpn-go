.PHONY: fmt test race vet lint fuzz-smoke fuzz bench audit interop

fmt:
	go fmt ./...

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run

fuzz-smoke:
	sh tests/fuzz/run.sh

fuzz:
	FUZZ_TIME=1m sh tests/fuzz/run.sh

bench:
	go test ./client ./internal/data -run '^$$' -bench 'Benchmark(IdleClient|Reconnect|DataRoundTrip|DiscardUnauthenticated)$$' -benchmem -benchtime 500ms -count 3

audit:
	python3 tools/release_audit.py --check docs/sbom.spdx.json
	go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...

interop:
	@test -n "$$OPENVPN_INTEROP_BIN" || { echo "Set OPENVPN_INTEROP_BIN to a pinned OpenVPN 2.6 test binary."; exit 1; }
	go test -v -count=1 ./tests/interop
