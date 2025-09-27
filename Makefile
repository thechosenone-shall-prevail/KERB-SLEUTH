.PHONY: build test clean simulate install

BINARY_NAME=kerb-sleuth
VERSION=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-X main.version=${VERSION}"

build:
	go build ${LDFLAGS} -o ${BINARY_NAME} ./cmd/kerb-sleuth

test:
	go test -v ./...

clean:
	go clean
	rm -f ${BINARY_NAME}
	rm -rf exports/
	rm -f results.json summary.csv sigma_rules.yml

simulate:
	go run ./cmd/kerb-sleuth simulate --dataset small --out tests/sample_data/

install: build
	mv ${BINARY_NAME} /usr/local/bin/

run-example: build simulate
	./${BINARY_NAME} scan --ad tests/sample_data/users_small.csv --out results.json --csv --siem

fmt:
	go fmt ./...

vet:
	go vet ./...

lint:
	golangci-lint run

deps:
	go mod download
	go mod tidy

# Cross compilation
build-linux:
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-linux-amd64 ./cmd/kerb-sleuth

build-windows:
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-windows-amd64.exe ./cmd/kerb-sleuth

build-mac:
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-darwin-amd64 ./cmd/kerb-sleuth

build-all: build-linux build-windows build-mac
