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

# Placeholder until the disposable OpenVPN server harness is implemented.
interop:
	@echo "Interoperability harness is scheduled for M2/M6; none is implemented yet."
