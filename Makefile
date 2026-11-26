.PHONY: fmt test race vet lint fuzz-smoke interop

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

# Placeholder until fuzz targets are implemented in M6.
fuzz-smoke:
	@echo "Fuzz targets are scheduled for M6; none are implemented yet."

interop:
	@test -n "$$OPENVPN_INTEROP_BIN" || { echo "Set OPENVPN_INTEROP_BIN to the pinned OpenVPN 2.6.23 test binary."; exit 1; }
	go test -v -count=1 ./tests/interop
