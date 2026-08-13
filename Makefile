.PHONY: build test vet race

build:
	go build -buildvcs=false -o caforge ./cmd/caforge

test:
	go test -buildvcs=false ./...

vet:
	go vet -buildvcs=false ./...

race:
	go test -buildvcs=false -race ./internal/pki ./internal/store ./internal/authority ./internal/certificate ./internal/revocation
