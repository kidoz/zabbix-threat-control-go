package agent2

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"io"
	"log/slog"

	"golang.zabbix.com/sdk/plugin"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/scanner"
	"github.com/kidoz/zabbix-threat-control-go/internal/zabbix"
)

// DefaultScanInterval is the default seconds between background scans.
const DefaultScanInterval = 3600

// ZTCPlugin implements Configurator, Runner and Exporter for Zabbix Agent 2.
type ZTCPlugin struct {
	plugin.Base

	cfg          *config.Config
	scanInterval int
	cache        *ScanCache

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewPlugin creates a new ZTCPlugin instance.
func NewPlugin() *ZTCPlugin {
	return &ZTCPlugin{
		cache:        NewScanCache(),
		scanInterval: DefaultScanInterval,
	}
}

// --- Configurator ---

// Configure is called by Agent 2 to pass config options.
func (p *ZTCPlugin) Configure(globalOptions *plugin.GlobalOptions, privateOptions any) {
	// privateOptions is a map[string]string from the agent2 config file
	// (Plugins.VulnersThreatControl.* keys).
	opts, ok := privateOptions.(map[string]string)
	if !ok {
		p.Errf("unexpected privateOptions type: %T", privateOptions)
		return
	}

	cfg := config.DefaultConfig()

	if v, ok := opts["VulnersApiKey"]; ok {
		cfg.Vulners.APIKey = v
	}
	if v, ok := opts["ZabbixFrontUrl"]; ok {
		cfg.Zabbix.FrontURL = v
	}
	if v, ok := opts["ZabbixApiUser"]; ok {
		cfg.Zabbix.APIUser = v
	}
	if v, ok := opts["ZabbixApiPassword"]; ok {
		cfg.Zabbix.APIPassword = v
	}
	if v, ok := opts["ZabbixServerFQDN"]; ok {
		cfg.Zabbix.ServerFQDN = v
	}
	if v, ok := opts["ZabbixServerPort"]; ok {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Zabbix.ServerPort = port
		}
	}
	if v, ok := opts["ZabbixSenderPath"]; ok {
		cfg.Zabbix.SenderPath = v
	}
	if v, ok := opts["ZabbixGetPath"]; ok {
		cfg.Zabbix.GetPath = v
	}
	if v, ok := opts["VulnersHost"]; ok {
		cfg.Vulners.Host = v
	}
	if v, ok := opts["VulnersRateLimit"]; ok {
		if rl, err := strconv.Atoi(v); err == nil {
			cfg.Vulners.RateLimit = rl
		}
	}
	if v, ok := opts["MinCVSS"]; ok {
		if cvss, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Scan.MinCVSS = cvss
		}
	}
	if v, ok := opts["Workers"]; ok {
		if w, err := strconv.Atoi(v); err == nil {
			cfg.Scan.Workers = w
		}
	}
	if v, ok := opts["Timeout"]; ok {
		if t, err := strconv.Atoi(v); err == nil {
			cfg.Scan.Timeout = t
		}
	}
	if v, ok := opts["ScanInterval"]; ok {
		if si, err := strconv.Atoi(v); err == nil {
			p.scanInterval = si
		}
	}

	p.cfg = cfg
}

// Validate checks mandatory configuration.
func (p *ZTCPlugin) Validate(privateOptions any) error {
	opts, ok := privateOptions.(map[string]string)
	if !ok {
		return fmt.Errorf("unexpected privateOptions type: %T", privateOptions)
	}
	if opts["VulnersApiKey"] == "" {
		return fmt.Errorf("Plugins.VulnersThreatControl.VulnersApiKey is required")
	}
	if opts["ZabbixApiUser"] == "" {
		return fmt.Errorf("Plugins.VulnersThreatControl.ZabbixApiUser is required")
	}
	if opts["ZabbixApiPassword"] == "" {
		return fmt.Errorf("Plugins.VulnersThreatControl.ZabbixApiPassword is required")
	}
	return nil
}

// --- Runner ---

// Start is called when Agent 2 starts the plugin.
func (p *ZTCPlugin) Start() {
	p.Infof("starting VulnersThreatControl plugin (scan interval: %ds)", p.scanInterval)

	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.wg.Add(1)
	go p.scanLoop(ctx)
}

// Stop is called when Agent 2 shuts down.
func (p *ZTCPlugin) Stop() {
	p.Infof("stopping VulnersThreatControl plugin")
	p.cancel()
	p.wg.Wait()
}

func (p *ZTCPlugin) scanLoop(ctx context.Context) {
	defer p.wg.Done()

	// Run immediately on start, then periodically.
	p.runScan(ctx)

	interval := p.scanInterval
	if interval <= 0 {
		interval = DefaultScanInterval
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.runScan(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (p *ZTCPlugin) runScan(ctx context.Context) {
	if p.cfg == nil {
		p.Errf("plugin not configured, skipping scan")
		return
	}

	// Create a nop logger for the scanner internals.
	// Plugin logging goes through p.Base (SDK logger).
	s, err := scanner.New(p.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		p.Errf("failed to create scanner: %s", err)
		return
	}
	defer func() { _ = s.Close() }()

	results, err := s.Scan(ctx, scanner.ScanOptions{})
	if err != nil {
		p.Errf("scan failed: %s", err)
		return
	}

	stats := s.GetAggregator().GetStatistics()
	p.cache.Update(results, stats)

	p.Infof("scan completed: %d hosts, %d vulns", results.HostsScanned, results.VulnerablePackages)
}

// --- Exporter ---

// Export handles item key requests from Agent 2.
func (p *ZTCPlugin) Export(key string, params []string, ctx plugin.ContextProvider) (any, error) {
	results := p.cache.Results()
	if results == nil {
		return nil, fmt.Errorf("no scan data available yet")
	}

	lldGen := scanner.NewLLDGenerator(p.cfg.Naming)

	switch key {
	case "vulners.hosts_lld":
		return marshalLLDData(lldGen.GenerateHostsLLD(results.Hosts))

	case "vulners.packages_lld":
		return marshalLLDData(lldGen.GeneratePackagesLLD(results.Packages))

	case "vulners.bulletins_lld":
		return marshalLLDData(lldGen.GenerateBulletinsLLD(results.Bulletins))

	case "vulners.host.score":
		if len(params) < 1 {
			return nil, fmt.Errorf("vulners.host.score requires hostid parameter")
		}
		hostID := params[0]
		for _, h := range results.Hosts {
			if h.HostID == hostID {
				return h.Score, nil
			}
		}
		return 0.0, nil

	case "vulners.package.score":
		if len(params) < 2 {
			return nil, fmt.Errorf("vulners.package.score requires name and version parameters")
		}
		name, version := params[0], params[1]
		for _, pkg := range results.Packages {
			if pkg.Name == name && pkg.Version == version {
				return pkg.Score, nil
			}
		}
		return 0.0, nil

	case "vulners.bulletin.score":
		if len(params) < 1 {
			return nil, fmt.Errorf("vulners.bulletin.score requires bulletin id parameter")
		}
		id := params[0]
		for _, b := range results.Bulletins {
			if b.ID == id {
				return b.Score, nil
			}
		}
		return 0.0, nil

	case "vulners.stats":
		if len(params) < 1 {
			return nil, fmt.Errorf("vulners.stats requires metric parameter")
		}
		return p.getStatMetric(params[0])

	default:
		return nil, fmt.Errorf("unknown key: %s", key)
	}
}

func (p *ZTCPlugin) getStatMetric(metric string) (any, error) {
	stats := p.cache.Stats()

	switch metric {
	case "total_hosts":
		return stats.TotalHosts, nil
	case "vuln_hosts":
		return stats.VulnerableHosts, nil
	case "total_vulns":
		return stats.TotalPackages, nil
	case "total_bulletins":
		return stats.TotalBulletins, nil
	case "total_cves":
		return stats.TotalCVEs, nil
	case "max_score":
		return stats.MaxCVSS, nil
	case "avg_score":
		return stats.AvgCVSS, nil
	default:
		return nil, fmt.Errorf("unknown stats metric: %s", metric)
	}
}

func marshalLLDData(data *zabbix.LLDData) (string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal LLD data: %w", err)
	}
	return string(b), nil
}
