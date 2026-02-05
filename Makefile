# ETC Collector - Makefile
# Go binary builder for multi-platform support

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "2.0.0-dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X main.Version=$(VERSION) \
	-X main.Commit=$(COMMIT) \
	-X main.BuildDate=$(BUILD_DATE)

BUILD_DIR := dist
BINARY := etc-collector
MODULE := github.com/etcsec-com/etc-collector

# Go settings
GO := go
GOFLAGS := -trimpath
CGO_ENABLED := 0

.PHONY: all build build-all test lint clean deps tidy help

# Default target
all: deps build

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Tidy modules
tidy:
	$(GO) mod tidy

# Build local binary
build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/etc-collector

# Build for all platforms
build-all: build-linux build-darwin build-windows

# Linux builds
build-linux:
	@echo "Building for Linux..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./cmd/etc-collector
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-linux-arm64 ./cmd/etc-collector

# macOS builds
build-darwin:
	@echo "Building for macOS..."
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 ./cmd/etc-collector
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 ./cmd/etc-collector

# Windows builds
build-windows:
	@echo "Building for Windows..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe ./cmd/etc-collector

# Run tests
test:
	$(GO) test -v -race -coverprofile=coverage.out ./...

# Run tests with coverage report
test-coverage: test
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Lint code
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Run: brew install golangci-lint"; \
	fi

# Format code
fmt:
	$(GO) fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

# Run the application
run:
	$(GO) run ./cmd/etc-collector $(ARGS)

# Run in server mode
run-server:
	$(GO) run ./cmd/etc-collector server $(ARGS)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Create release archives
release: build-all
	@echo "Creating release archives..."
	@mkdir -p $(BUILD_DIR)/release
	cd $(BUILD_DIR) && tar czf release/$(BINARY)-linux-amd64.tar.gz $(BINARY)-linux-amd64
	cd $(BUILD_DIR) && tar czf release/$(BINARY)-linux-arm64.tar.gz $(BINARY)-linux-arm64
	cd $(BUILD_DIR) && tar czf release/$(BINARY)-darwin-amd64.tar.gz $(BINARY)-darwin-amd64
	cd $(BUILD_DIR) && tar czf release/$(BINARY)-darwin-arm64.tar.gz $(BINARY)-darwin-arm64
	cd $(BUILD_DIR) && zip release/$(BINARY)-windows-amd64.zip $(BINARY)-windows-amd64.exe
	cd $(BUILD_DIR)/release && sha256sum *.tar.gz *.zip > checksums.txt
	@echo "Release artifacts in $(BUILD_DIR)/release/"

# Docker build
docker:
	docker build -t etcsec/etc-collector:$(VERSION) --build-arg VERSION=$(VERSION) .
	docker tag etcsec/etc-collector:$(VERSION) etcsec/etc-collector:latest

# Generate mocks (requires mockgen)
generate:
	$(GO) generate ./...

# Check for outdated dependencies
outdated:
	$(GO) list -u -m all

# Security scan
security:
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed. Run: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

# Generate RSA keys for JWT
keys:
	@mkdir -p keys
	openssl genrsa -out keys/private.pem 2048
	openssl rsa -in keys/private.pem -pubout -out keys/public.pem
	@chmod 600 keys/private.pem
	@echo "Keys generated in keys/ directory"

# Install locally
install: build
	sudo cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(BINARY)"

# Show version info
version:
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"

# Help
help:
	@echo "ETC Collector - Makefile targets"
	@echo ""
	@echo "Build:"
	@echo "  build        - Build local binary"
	@echo "  build-all    - Build for all platforms"
	@echo "  build-linux  - Build for Linux (amd64, arm64)"
	@echo "  build-darwin - Build for macOS (amd64, arm64)"
	@echo "  build-windows- Build for Windows (amd64)"
	@echo ""
	@echo "Development:"
	@echo "  run          - Run the application"
	@echo "  run-server   - Run in server mode"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo ""
	@echo "Release:"
	@echo "  release      - Build and package all platforms"
	@echo "  docker       - Build Docker image"
	@echo ""
	@echo "Maintenance:"
	@echo "  deps         - Download dependencies"
	@echo "  tidy         - Tidy modules"
	@echo "  clean        - Clean build artifacts"
	@echo "  outdated     - Check for outdated deps"
	@echo "  security     - Run security scan"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=$(VERSION)"
	@echo "  ARGS=        - Pass arguments to run targets"
