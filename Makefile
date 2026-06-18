build:
	go build -ldflags "-X main.version=$(shell git describe --tags --always)" -o redactr-community ./cmd/redactr-community

test:
	go test ./...

.PHONY: build test
