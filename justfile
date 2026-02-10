project  := "github.com/kidoz/zabbix-threat-control-go"
version  := `git describe --tags --always --dirty 2>/dev/null || echo "0.1.0"`
commit   := `git rev-parse --short HEAD 2>/dev/null || echo "unknown"`
build_time := `date -u +%Y-%m-%dT%H:%M:%SZ`
ldflags  := "-s -w -X " + project + "/cmd.Version=" + version + " -X " + project + "/cmd.BuildTime=" + build_time + " -X " + project + "/cmd.GitCommit=" + commit

export CGO_ENABLED := "0"

# ─── Default ──────────────────────────────────────────────────

# Show available recipes
default:
    @just --list

# ─── Build ────────────────────────────────────────────────────

# Build both binaries
build: build-ztc build-plugin

# Build ztc CLI
build-ztc:
    go build -ldflags "{{ldflags}}" -o ztc .

# Build ztc-plugin (Agent 2)
build-plugin:
    go build -ldflags "{{ldflags}}" -o ztc-plugin ./cmd/ztc-plugin/

# Remove build artifacts
clean:
    rm -f ztc ztc-plugin
    rm -rf dist/ build/

# ─── Quality ──────────────────────────────────────────────────

# Run all checks (lint + vet + test)
check: lint vet test

# Run tests
test *args='./...':
    go test {{args}}

# Run tests with verbose output
test-verbose *args='./...':
    go test -v {{args}}

# Run tests with race detector
test-race *args='./...':
    CGO_ENABLED=1 go test -race {{args}}

# Run go vet
vet:
    go vet ./...

# Run golangci-lint
lint:
    golangci-lint run ./...

# Run golangci-lint with auto-fix
lint-fix:
    golangci-lint run --fix ./...

# Format code
fmt:
    gofumpt -w .

# Format code (standard gofmt)
fmt-std:
    gofmt -s -w .

# Check formatting without writing
fmt-check:
    @test -z "$(gofmt -l .)" || (echo "Files need formatting:" && gofmt -l . && exit 1)

# Tidy go.mod
tidy:
    go mod tidy

# Verify dependencies
mod-verify:
    go mod verify

# ─── Packaging (GoReleaser) ───────────────────────────────────

# Build local snapshot packages (deb + rpm + archives, no publish)
snapshot:
    goreleaser release --snapshot --clean

# Build binaries only (snapshot, no packages)
snapshot-build:
    goreleaser build --snapshot --clean

# Validate GoReleaser config
release-check:
    goreleaser check

# ─── Development ──────────────────────────────────────────────

# Run ztc with args (e.g. just run version)
run *args:
    go run . {{args}}

# Run ztc-plugin
run-plugin *args:
    go run ./cmd/ztc-plugin/ {{args}}

# Install tools (golangci-lint, gofumpt, govulncheck)
tools:
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
    go install mvdan.cc/gofumpt@latest
    go install golang.org/x/vuln/cmd/govulncheck@latest

# Scan dependencies for known vulnerabilities
vulncheck:
    govulncheck ./...

# Show module dependency graph
deps:
    go mod graph

# Show outdated direct dependencies
outdated:
    go list -u -m -json all 2>/dev/null | go-mod-outdated -direct-only || echo "Install: go install github.com/psampaz/go-mod-outdated@latest"

# ─── Integration Testing ────────────────────────────────────────

# Start Zabbix Docker Compose stack
compose-up:
    cd integration && docker compose up -d

# Stop and remove Zabbix Docker Compose stack
compose-down:
    cd integration && docker compose down -v

# Show Zabbix stack logs
compose-logs *args:
    cd integration && docker compose logs {{args}}

# Run legacy shim tests (no Docker required)
test-shims:
    bash integration/scripts/verify-legacy-shims.sh

# Run integration tests
integration-test:
    bash integration/scripts/run-tests.sh

# Run integration tests for a specific Zabbix version
integration-test-version version:
    ZABBIX_VERSION={{version}}-latest ZABBIX_AGENT2_VERSION={{version}}-ubuntu-latest \
        bash integration/scripts/run-tests.sh
