package fixer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/zabbix"
)

// Fixer orchestrates vulnerability remediation
type Fixer struct {
	cfg          *config.Config
	log          *zap.Logger
	zabbixClient *zabbix.Client
	executor     *Executor
}

// New creates a new fixer
func New(cfg *config.Config, log *zap.Logger) (*Fixer, error) {
	zabbixClient, err := zabbix.NewClient(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create Zabbix client: %w", err)
	}

	return &Fixer{
		cfg:          cfg,
		log:          log,
		zabbixClient: zabbixClient,
		executor:     NewExecutor(cfg, log),
	}, nil
}

// Plan creates a fix plan for the given options
func (f *Fixer) Plan(opts FixOptions) (*FixPlan, error) {
	ctx := context.Background()
	plan := &FixPlan{}

	// Reject virtual hosts — they have 127.0.0.1 loopback interfaces and
	// are never valid fix targets. This prevents accidental remediation
	// against localhost when {HOST.HOST} from a Zabbix action macro is
	// passed through (it resolves to virtual hosts like "vulners.packages").
	if opts.HostName != "" && f.isVirtualHost(opts.HostName) {
		return nil, fmt.Errorf("host %q is a ZTC virtual host, not a real monitored host — refusing to fix", opts.HostName)
	}

	// Resolve host name to host ID if provided
	if opts.HostName != "" && opts.HostID == "" {
		host, err := f.zabbixClient.GetHostByNameCtx(ctx, opts.HostName)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve host name %q: %w", opts.HostName, err)
		}
		opts.HostID = host.HostID
		f.log.Info("Resolved host name to ID", zap.String("host_name", opts.HostName), zap.String("host_id", opts.HostID))
	}

	// If a specific host is requested
	if opts.HostID != "" {
		hostPlan, err := f.planForHost(ctx, opts.HostID)
		if err != nil {
			return nil, err
		}
		if hostPlan != nil {
			plan.Hosts = append(plan.Hosts, *hostPlan)
		}
		return plan, nil
	}

	// If a bulletin is specified, find all affected hosts
	if opts.BulletinID != "" {
		return f.planForBulletin(ctx, opts.BulletinID)
	}

	return nil, fmt.Errorf("either --host, --host-name, or --bulletin must be specified")
}

// planForHost creates a fix plan for a specific host
func (f *Fixer) planForHost(ctx context.Context, hostID string) (*HostFixPlan, error) {
	host, err := f.zabbixClient.GetHostByIDCtx(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("failed to get host: %w", err)
	}

	// Get host's vulnerable packages from previously-pushed scan data.
	packages := f.getVulnerablePackages(ctx, hostID)

	if len(packages) == 0 {
		f.log.Warn("No per-package vulnerability data found; fix will perform a full system update",
			zap.String("host", host.Name))
	}

	// Get host address and agent port
	ip, agentPort := f.getHostAddress(host)
	if ip == "" {
		return nil, fmt.Errorf("no IP address found for host %s", host.Name)
	}

	// Get OS info to generate appropriate command
	osName := f.getHostOS(ctx, hostID)

	// Generate fix command
	command := f.executor.GenerateFixCommand(osName, packages)

	return &HostFixPlan{
		HostID:    hostID,
		Name:      host.Name,
		IP:        ip,
		AgentPort: agentPort,
		Packages:  packages,
		Command:   command,
	}, nil
}

// planForBulletin creates a fix plan for a bulletin across affected hosts only.
// It queries the bulletins LLD data to identify which hosts and packages are
// affected by the specific bulletin, rather than upgrading everything.
func (f *Fixer) planForBulletin(ctx context.Context, bulletinID string) (*FixPlan, error) {
	f.log.Info("Creating fix plan for bulletin", zap.String("bulletin", bulletinID))

	plan := &FixPlan{}

	affectedHostIDs, affectedPkgs, err := f.getBulletinInfo(ctx, bulletinID)
	if err != nil {
		return nil, fmt.Errorf("failed to get bulletin info: %w", err)
	}

	// Build a set for quick package lookup
	pkgSet := make(map[string]bool, len(affectedPkgs))
	for _, pkg := range affectedPkgs {
		pkgSet[pkg] = true
	}

	for _, hostID := range affectedHostIDs {
		host, err := f.zabbixClient.GetHostByIDCtx(ctx, hostID)
		if err != nil {
			f.log.Warn("Failed to get host, skipping", zap.Error(err), zap.String("host", hostID))
			continue
		}

		// Get only the bulletin's packages that exist on this host
		allPackages := f.getVulnerablePackages(ctx, hostID)
		var packages []string
		for _, pkg := range allPackages {
			if pkgSet[pkg] {
				packages = appendUniqueStr(packages, pkg)
			}
		}
		if len(packages) == 0 {
			continue
		}

		ip, agentPort := f.getHostAddress(host)
		if ip == "" {
			continue
		}

		osName := f.getHostOS(ctx, hostID)
		command := f.executor.GenerateFixCommand(osName, packages)

		plan.Hosts = append(plan.Hosts, HostFixPlan{
			HostID:    hostID,
			Name:      host.Name,
			IP:        ip,
			AgentPort: agentPort,
			Packages:  packages,
			Command:   command,
		})
	}

	if len(plan.Hosts) == 0 {
		f.log.Warn("No hosts with stored vulnerability data found for this bulletin")
	}

	return plan, nil
}

// getBulletinInfo queries the bulletins LLD data from the virtual host to find
// affected host IDs and package names for a specific bulletin.
func (f *Fixer) getBulletinInfo(ctx context.Context, bulletinID string) (hostIDs []string, pkgs []string, err error) {
	lldJSON, err := f.zabbixClient.GetItemValueCtx(ctx, f.cfg.Naming.BulletinsHost, "vulners.bulletins_lld")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get bulletins LLD: %w", err)
	}
	if lldJSON == "" {
		return nil, nil, fmt.Errorf("no bulletins LLD data found; run 'ztc scan' first")
	}

	var lldData zabbix.LLDData
	if err := json.Unmarshal([]byte(lldJSON), &lldData); err != nil {
		return nil, nil, fmt.Errorf("failed to parse bulletins LLD: %w", err)
	}

	for _, entry := range lldData.Data {
		id, _ := entry["{#B.ID}"].(string)
		if id != bulletinID {
			continue
		}

		// Parse comma-separated host IDs
		if hostsStr, ok := entry["{#B.HOSTS}"].(string); ok && hostsStr != "" {
			hostIDs = strings.Split(hostsStr, ",")
		}
		// Parse comma-separated package strings and extract just the name.
		// {#B.PKGS} contains raw package strings like "nginx 1.18.0 amd64"
		// but getVulnerablePackages() returns just the name portion.
		if pkgsStr, ok := entry["{#B.PKGS}"].(string); ok && pkgsStr != "" {
			for _, raw := range strings.Split(pkgsStr, ",") {
				name := strings.Fields(raw)[0]
				pkgs = appendUniqueStr(pkgs, name)
			}
		}
		return hostIDs, pkgs, nil
	}

	return nil, nil, fmt.Errorf("bulletin %q not found in LLD data", bulletinID)
}

// Execute executes a fix plan
func (f *Fixer) Execute(plan *FixPlan, opts FixOptions) (*FixResults, error) {
	ctx := context.Background()
	results := &FixResults{}

	var wg sync.WaitGroup
	var mu sync.Mutex
	workers := f.cfg.Scan.Workers
	if workers <= 0 {
		workers = 1
	}
	semaphore := make(chan struct{}, workers)

	sshUser := opts.SSHUser
	if sshUser == "" {
		sshUser = "root"
	}

	for _, hostPlan := range plan.Hosts {
		wg.Add(1)
		go func(hp HostFixPlan) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := f.executeOnHost(ctx, &hp, opts.UseSSH, sshUser)

			mu.Lock()
			results.Hosts = append(results.Hosts, result)
			if result.Success {
				results.Successful++
			} else {
				results.Failed++
			}
			mu.Unlock()
		}(hostPlan)
	}

	wg.Wait()
	return results, nil
}

// executeOnHost executes the fix on a single host
func (f *Fixer) executeOnHost(ctx context.Context, plan *HostFixPlan, useSSH bool, sshUser string) HostFixResult {
	result := HostFixResult{
		HostID: plan.HostID,
		Name:   plan.Name,
	}

	f.log.Info("Executing fix command",
		zap.String("host", plan.Name),
		zap.String("ip", plan.IP),
		zap.String("command", plan.Command),
		zap.Bool("ssh", useSSH),
	)

	var output string
	var err error
	if useSSH {
		output, err = f.executor.ExecuteWithRetry(ctx, func() (string, error) {
			return f.executor.ExecuteViaSSH(ctx, plan.IP, sshUser, plan.Command)
		}, 2)
	} else {
		output, err = f.executor.ExecuteWithRetry(ctx, func() (string, error) {
			return f.executor.ExecuteViaAgent(ctx, plan.IP, plan.AgentPort, plan.Command)
		}, 2)
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		f.log.Error("Fix execution failed", zap.Error(err), zap.String("host", plan.Name))
	} else {
		result.Success = true
		result.Output = output
		f.log.Info("Fix executed successfully", zap.String("host", plan.Name))
	}

	return result
}

// getVulnerablePackages queries the packages LLD data on the virtual packages
// host to find which packages affect the given host. The scanner publishes
// all package data to the virtual host (e.g. "vulners.packages"), not to
// individual monitored hosts, so we parse the LLD JSON and filter by host ID.
// Returns package names suitable for the OS package manager.
func (f *Fixer) getVulnerablePackages(ctx context.Context, hostID string) []string {
	lldJSON, err := f.zabbixClient.GetItemValueCtx(ctx, f.cfg.Naming.PackagesHost, "vulners.packages_lld")
	if err != nil {
		f.log.Debug("Failed to get packages LLD data", zap.Error(err), zap.String("host", hostID))
		return nil
	}
	if lldJSON == "" {
		f.log.Debug("No packages LLD data found; run 'ztc scan' first", zap.String("host", hostID))
		return nil
	}

	var lldData zabbix.LLDData
	if err := json.Unmarshal([]byte(lldJSON), &lldData); err != nil {
		f.log.Debug("Failed to parse packages LLD data", zap.Error(err))
		return nil
	}

	var packages []string
	for _, entry := range lldData.Data {
		// {#P.HOSTS} contains comma-separated host IDs
		hostsStr, _ := entry["{#P.HOSTS}"].(string)
		if hostsStr == "" {
			continue
		}
		// Check if this host is in the affected hosts list
		found := false
		for _, hid := range strings.Split(hostsStr, ",") {
			if hid == hostID {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		// Extract package name
		if name, ok := entry["{#P.NAME}"].(string); ok && name != "" {
			packages = appendUniqueStr(packages, name)
		}
	}

	return packages
}

// appendUniqueStr appends s to slice only if not already present.
func appendUniqueStr(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

// getHostAddress extracts the IP/DNS address and agent port from a host.
// Prefers the main agent interface (type=1, main=1), matching Python's
// hostinterface.get(filter={"main":"1","type":"1"}).
func (f *Fixer) getHostAddress(host *zabbix.Host) (address, port string) {
	for _, iface := range host.Interfaces {
		if iface.Main == "1" && iface.Type == "1" {
			port = iface.Port
			if iface.UseIP == "1" && iface.IP != "" {
				return iface.IP, port
			}
			if iface.DNS != "" {
				return iface.DNS, port
			}
		}
	}

	// Fallback: any main interface
	for _, iface := range host.Interfaces {
		if iface.Main == "1" {
			port = iface.Port
			if iface.UseIP == "1" && iface.IP != "" {
				return iface.IP, port
			}
			if iface.DNS != "" {
				return iface.DNS, port
			}
		}
	}

	// Last resort: any interface
	for _, iface := range host.Interfaces {
		if iface.IP != "" {
			return iface.IP, iface.Port
		}
		if iface.DNS != "" {
			return iface.DNS, iface.Port
		}
	}

	return "", ""
}

// getHostOS gets the OS name for a host
func (f *Fixer) getHostOS(ctx context.Context, hostID string) string {
	items, err := f.zabbixClient.GetHostItemsCtx(ctx, hostID, "system.sw.os")
	if err != nil {
		return ""
	}

	for _, item := range items {
		if item.Value != "" {
			return item.Value
		}
	}

	return ""
}

// isVirtualHost returns true if the given hostname is a ZTC virtual host.
// Virtual hosts (vulners.hosts, vulners.packages, etc.) have 127.0.0.1
// loopback interfaces and must never be targeted for remediation.
func (f *Fixer) isVirtualHost(name string) bool {
	n := f.cfg.Naming
	switch name {
	case n.HostsHost, n.PackagesHost, n.BulletinsHost, n.StatisticsHost:
		return true
	}
	return false
}

// Close releases resources
func (f *Fixer) Close() error {
	return f.zabbixClient.Close()
}
