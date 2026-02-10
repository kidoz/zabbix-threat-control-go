package scanner

import (
	"context"
	"fmt"
	"strings"

	"log/slog"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/telemetry"
	"github.com/kidoz/zabbix-threat-control-go/internal/zabbix"
)

// HostData contains all relevant data for a host
type HostData struct {
	Host      *zabbix.Host
	OSName    string
	OSVersion string
	Packages  []string
}

// HostMatrix fetches and organizes host data from Zabbix
type HostMatrix struct {
	cfg    *config.Config
	log    *slog.Logger
	client *zabbix.Client
}

// NewHostMatrix creates a new host matrix
func NewHostMatrix(cfg *config.Config, log *slog.Logger, client *zabbix.Client) *HostMatrix {
	return &HostMatrix{
		cfg:    cfg,
		log:    log,
		client: client,
	}
}

// FetchHosts fetches hosts with the OS-Report template and their data
func (hm *HostMatrix) FetchHosts(ctx context.Context, opts ScanOptions) ([]HostData, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "HostMatrix.FetchHosts")
	defer span.End()

	// Get hosts with OS-Report template
	hosts, err := hm.client.GetHostsWithTemplateCtx(ctx, hm.cfg.Scan.OSReportTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to get hosts: %w", err)
	}

	hm.log.Info("Found hosts with OS-Report template", slog.Int("count", len(hosts)))

	// Filter by specific host IDs if provided
	if len(opts.HostIDs) > 0 {
		hostIDSet := make(map[string]bool)
		for _, id := range opts.HostIDs {
			hostIDSet[id] = true
		}

		var filtered []zabbix.Host
		for _, h := range hosts {
			if hostIDSet[h.HostID] {
				filtered = append(filtered, h)
			}
		}
		hosts = filtered
		hm.log.Info("Filtered to specific hosts", slog.Int("count", len(hosts)))
	}

	// Apply limit
	if opts.Limit > 0 && len(hosts) > opts.Limit {
		hosts = hosts[:opts.Limit]
		hm.log.Info("Applied host limit", slog.Int("limit", opts.Limit))
	}

	// Fetch data for each host
	var hostData []HostData
	for _, host := range hosts {
		data, err := hm.fetchHostData(ctx, &host)
		if err != nil {
			hm.log.Warn("Failed to fetch host data", slog.Any("error", err), slog.String("host", host.Name))
			continue
		}

		if data != nil {
			hostData = append(hostData, *data)
		}
	}

	return hostData, nil
}

// fetchHostData fetches OS and package data for a single host
func (hm *HostMatrix) fetchHostData(ctx context.Context, host *zabbix.Host) (*HostData, error) {
	hm.log.Debug("Fetching host data", slog.String("host", host.Name))

	// Get OS name item
	osItems, err := hm.client.GetHostItemsCtx(ctx, host.HostID, "system.sw.os")
	if err != nil {
		return nil, fmt.Errorf("failed to get OS items: %w", err)
	}

	var osName, osVersion string
	for _, item := range osItems {
		if item.Value != "" {
			osName, osVersion = parseOSInfo(item.Value)
			break
		}
	}

	if osName == "" {
		hm.log.Debug("No OS information available", slog.String("host", host.Name))
		return nil, nil
	}

	// Get packages item
	pkgItems, err := hm.client.GetHostItemsCtx(ctx, host.HostID, "system.sw.packages")
	if err != nil {
		return nil, fmt.Errorf("failed to get package items: %w", err)
	}

	var packages []string
	for _, item := range pkgItems {
		if item.Value != "" {
			packages = parsePackageList(item.Value)
			break
		}
	}

	if len(packages) == 0 {
		hm.log.Debug("No package information available", slog.String("host", host.Name))
		return nil, nil
	}

	// Normalize OS name for Vulners API
	osName = NormalizeOSName(osName)
	osVersion = ExtractOSVersion(osVersion)

	// Host data validation (matching Python behavior)
	if reason := validateHostData(osVersion, packages); reason != "" {
		hm.log.Debug("Excluded host", slog.String("host", host.Name), slog.String("reason", reason))
		return nil, nil
	}

	hm.log.Debug("Fetched host data",
		slog.String("host", host.Name),
		slog.String("os", osName),
		slog.String("version", osVersion),
		slog.Int("packages", len(packages)),
	)

	return &HostData{
		Host:      host,
		OSName:    osName,
		OSVersion: osVersion,
		Packages:  packages,
	}, nil
}

// validateHostData checks whether a host's data is valid for scanning.
// Returns an empty string if valid, or a reason string if the host should be excluded.
// Matches Python's exclusion rules: OS version "0.0", <=5 packages, or "report.py" in packages.
func validateHostData(osVersion string, packages []string) string {
	if osVersion == "0.0" {
		return "OS version 0.0"
	}
	if len(packages) <= 5 {
		return "too few packages"
	}
	for _, pkg := range packages {
		if strings.Contains(pkg, "report.py") {
			return "report.py in packages"
		}
	}
	return ""
}

// parseOSInfo parses the OS information string
func parseOSInfo(osInfo string) (name, version string) {
	// Handle various formats:
	// "Ubuntu 20.04.3 LTS"
	// "CentOS Linux release 7.9.2009 (Core)"
	// "Red Hat Enterprise Linux Server release 7.9.2009 (Maipo)"
	// "Debian GNU/Linux 11 (bullseye)"

	osInfo = strings.TrimSpace(osInfo)

	parts := strings.Fields(osInfo)
	if len(parts) == 0 {
		return "", ""
	}

	// Collect all words before the first version-like token as the OS name.
	// This handles multi-word names like "Red Hat Enterprise Linux".
	var nameParts []string
	for _, part := range parts {
		if len(part) > 0 && part[0] >= '0' && part[0] <= '9' {
			version = part
			break
		}
		nameParts = append(nameParts, part)
	}

	name = strings.ToLower(strings.Join(nameParts, " "))
	return name, version
}

// parsePackageList parses the package list from Zabbix
func parsePackageList(pkgList string) []string {
	// Handle various formats:
	// One package per line
	// Package format varies by distro:
	// - Debian/Ubuntu: "name version arch"
	// - RedHat/CentOS: "name-version.arch"

	lines := strings.Split(pkgList, "\n")
	var packages []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		packages = append(packages, line)
	}

	return packages
}
