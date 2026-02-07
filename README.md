# Zabbix Threat Control (ZTC)

[![CI](https://github.com/kidoz/zabbix-threat-control-go/actions/workflows/ci.yml/badge.svg)](https://github.com/kidoz/zabbix-threat-control-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/kidoz/zabbix-threat-control-go)](https://goreportcard.com/report/github.com/kidoz/zabbix-threat-control-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/kidoz/zabbix-threat-control-go.svg)](https://pkg.go.dev/github.com/kidoz/zabbix-threat-control-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Zabbix Threat Control transforms Zabbix monitoring into a vulnerability assessment system using the Vulners API. It scans hosts monitored by Zabbix for security vulnerabilities in installed packages and reports them back to Zabbix for centralized monitoring and alerting.

This is a Go reimplementation of the original [zabbix-threat-control](https://github.com/vulnersCom/zabbix-threat-control) Python project.

## Installation

### From releases

Download the latest binary from the [Releases](https://github.com/kidoz/zabbix-threat-control-go/releases) page.

### From source

```bash
go install github.com/kidoz/zabbix-threat-control-go@latest
```

### System packages

RPM and DEB packages are available in releases. The package installs as `zabbix-threat-control-main` and symlinks into `/opt/monitoring/zabbix-threat-control/`.

## Configuration

ZTC reads its configuration from a YAML or legacy INI file.

- **Default path:** `/opt/monitoring/zabbix-threat-control/ztc.conf`
- **Example config:** [`configs/ztc.yaml.example`](configs/ztc.yaml.example)

### YAML format (recommended)

```yaml
zabbix:
  front_url: "http://zabbix.example.com"
  api_user: Admin
  api_password: zabbix
vulners:
  api_key: YOUR_VULNERS_API_KEY
scan:
  min_cvss: 1.0
  workers: 4
```

### Legacy INI format

The original Python project's `.conf` format is supported with limitations. Files with `.conf` or `.ini` extensions are auto-detected as INI. Python-only keys (`VulnersProxyHost`, `TrustedZabbixUsers`, `UseZabbixAgentToFix`, `SSHUser`, `LogFile`, `DebugLevel`, etc.) are recognized but silently skipped with a warning. Use `ztc migrate-config` to convert to the new YAML format.

### Environment variable overrides

All settings can be overridden via environment variables with the `ZTC_` prefix:

```bash
export ZTC_ZABBIX_FRONT_URL=http://zabbix.example.com
export ZTC_VULNERS_API_KEY=your-key
```

### Migrating from INI to YAML

```bash
ztc migrate-config --input /opt/monitoring/zabbix-threat-control/ztc.conf --output /etc/ztc.yaml
```

## Usage

```bash
# Scan hosts for vulnerabilities and push results to Zabbix
ztc scan

# Scan specific hosts
ztc scan --hosts host1,host2

# Prepare Zabbix (create templates, virtual hosts, dashboard)
ztc prepare

# Fix vulnerabilities on a specific host
ztc fix --host HOST_ID

# Fix vulnerabilities for a specific bulletin
ztc fix --bulletin BULLETIN_ID

# Show version
ztc version

# Migrate legacy config
ztc migrate-config
```

## Zabbix Agent 2 Plugin

ZTC can also run as a Zabbix Agent 2 loadable plugin (`ztc-plugin`), allowing scan results to be collected directly by the agent.

```bash
go build -o ztc-plugin ./cmd/ztc-plugin/
```

The plugin binary is Linux-only (Zabbix Agent 2 requirement).

## Architecture

```
CLI (ztc)
  +-- scanner  --> Zabbix API (host/item data)
  |                Vulners API (vulnerability audit)
  |                zabbix_sender (push results)
  +-- fixer    --> Zabbix API (host lookup)
  |                SSH / zabbix_get (remote execution)
  +-- prepare  --> Zabbix API (templates, hosts, dashboard)
```

## Development

Requires Go 1.25+. A [justfile](https://github.com/casey/just) is provided for common tasks:

```bash
# Install dev tools (golangci-lint, gofumpt, wire, govulncheck)
just tools

# Build both binaries
just build

# Run tests
just test

# Run linter
just lint

# Run all quality checks (lint + vet + test)
just check

# Scan dependencies for known vulnerabilities
just vulncheck

# Regenerate Wire dependency injection code
just wire

# Verify generated Wire code is up to date
just wire-check

# Format code
just fmt
```

### Dependency injection

CLI command wiring uses [Google Wire](https://github.com/google/wire) for compile-time dependency injection. The generated file `cmd/wire_gen.go` is committed to the repo so builds don't require the `wire` tool. If you change provider signatures or add dependencies:

```bash
just wire          # regenerate cmd/wire_gen.go
just wire-check    # verify it matches (CI runs this)
```

### Manual commands

```bash
go build -o ztc .
go build -o ztc-plugin ./cmd/ztc-plugin/
go test ./...
go vet ./...
golangci-lint run ./...
govulncheck ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
