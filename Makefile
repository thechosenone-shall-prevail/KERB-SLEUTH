.PHONY: build test clean simulate install build-all docker-build docker-run release

BINARY_NAME=kerb-sleuth
VERSION=$(shell git describe --tags --always --dirty)
LDFLAGS=-ldflags "-s -w -X main.version=${VERSION}"
DOCKER_IMAGE=kerb-sleuth:latest

# Development targets
build:
	go build ${LDFLAGS} -o ${BINARY_NAME} ./cmd/kerb-sleuth

test:
	go test -v ./...

test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	go clean
	rm -f ${BINARY_NAME}*
	rm -rf dist/
	rm -rf exports/
	rm -f results.json summary.csv sigma_rules.yml test_results.json
	rm -f coverage.out coverage.html

simulate:
	go run ./cmd/kerb-sleuth simulate --dataset small --out tests/sample_data/

install: build
	sudo mv ${BINARY_NAME} /usr/local/bin/

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

# Cross compilation targets
build-linux:
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-linux-amd64 ./cmd/kerb-sleuth

build-linux-arm:
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o ${BINARY_NAME}-linux-arm64 ./cmd/kerb-sleuth

build-windows:
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-windows-amd64.exe ./cmd/kerb-sleuth

build-mac:
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-darwin-amd64 ./cmd/kerb-sleuth

build-mac-arm:
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${BINARY_NAME}-darwin-arm64 ./cmd/kerb-sleuth

build-all: clean build-linux build-linux-arm build-windows build-mac build-mac-arm

# Docker targets
docker-build:
	docker build -t ${DOCKER_IMAGE} .

docker-run:
	docker run --rm -it -v ${PWD}/data:/data ${DOCKER_IMAGE}

docker-shell:
	docker run --rm -it -v ${PWD}/data:/data --entrypoint /bin/sh ${DOCKER_IMAGE}

docker-clean:
	docker rmi ${DOCKER_IMAGE} 2>/dev/null || true

# Release targets
release-prep:
	./prepare-release.sh

release: clean test vet build-all docker-build
	@echo "Release build complete. Run 'make release-prep' to prepare for GitHub release."

# Security scanning
security-scan:
	gosec ./...

# Benchmarks
bench:
	go test -bench=. -benchmem ./...

build-all: build-linux build-windows build-mac
