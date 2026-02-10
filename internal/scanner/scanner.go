package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"log/slog"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"

	vulners "github.com/kidoz/go-vulners"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/telemetry"
	"github.com/kidoz/zabbix-threat-control-go/internal/zabbix"
)

// Scanner orchestrates vulnerability scanning
type Scanner struct {
	cfg           *config.Config
	log           *slog.Logger
	zabbixClient  *zabbix.Client
	vulnersClient *vulners.Client
	sender        *zabbix.Sender
	hostMatrix    *HostMatrix
	aggregator    *Aggregator
	lldGenerator  *LLDGenerator
}

// New creates a new scanner
func New(cfg *config.Config, log *slog.Logger) (*Scanner, error) {
	zabbixClient, err := zabbix.NewClient(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create Zabbix client: %w", err)
	}

	// Create an instrumented HTTP client for Vulners
	instrumentedHTTP := &http.Client{
		Timeout:   time.Duration(cfg.Scan.Timeout) * time.Second,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}

	vulnersClient, err := vulners.NewClient(cfg.Vulners.APIKey,
		vulners.WithHTTPClient(instrumentedHTTP),
		vulners.WithRateLimit(float64(cfg.Vulners.RateLimit), cfg.Vulners.RateLimit*2),
		vulners.WithBaseURL(cfg.Vulners.Host),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vulners client: %w", err)
	}

	return &Scanner{
		cfg:           cfg,
		log:           log,
		zabbixClient:  zabbixClient,
		vulnersClient: vulnersClient,
		sender:        zabbix.NewSender(cfg, log),
		hostMatrix:    NewHostMatrix(cfg, log, zabbixClient),
		aggregator:    NewAggregator(),
		lldGenerator:  NewLLDGenerator(cfg.Naming),
	}, nil
}

// Scan performs a vulnerability scan. Pass a cancellable context to allow
// the caller (CLI signal handler, Agent 2 plugin) to abort in-flight work.
func (s *Scanner) Scan(ctx context.Context, opts ScanOptions) (*ScanResults, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "Scanner.Scan")
	defer span.End()

	// Fetch hosts with OS-Report data
	s.log.Info("Fetching hosts from Zabbix...")
	hosts, err := s.hostMatrix.FetchHosts(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch hosts: %w", err)
	}

	if len(hosts) == 0 {
		s.log.Warn("No hosts with OS-Report data found")
		return &ScanResults{}, nil
	}

	s.log.Info("Starting vulnerability scan", slog.Int("hosts", len(hosts)))

	// Reset aggregator so repeated calls don't accumulate stale data.
	s.aggregator.Reset()

	// Scan hosts concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex
	workers := s.cfg.Scan.Workers
	if workers <= 0 {
		workers = 1
	}
	semaphore := make(chan struct{}, workers)

	for _, hostData := range hosts {
		wg.Add(1)
		go func(hd HostData) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			entry, err := s.scanHost(ctx, &hd)
			if err != nil {
				s.log.Warn("Failed to scan host", slog.Any("error", err), slog.String("host", hd.Host.Name))
				return
			}

			if entry != nil {
				mu.Lock()
				s.aggregator.AddHost(*entry)
				mu.Unlock()
			}
		}(hostData)
	}

	wg.Wait()

	return s.aggregator.GetResults(), nil
}

// scanHost scans a single host for vulnerabilities
func (s *Scanner) scanHost(ctx context.Context, hostData *HostData) (*HostEntry, error) {
	ctx, span := telemetry.Tracer().Start(ctx, "Scanner.scanHost")
	defer span.End()

	span.SetAttributes(
		attribute.String("host.name", hostData.Host.Name),
		attribute.String("os", hostData.OSName),
		attribute.Int("package.count", len(hostData.Packages)),
	)

	s.log.Debug("Scanning host",
		slog.String("host", hostData.Host.Name),
		slog.String("os", hostData.OSName),
		slog.String("version", hostData.OSVersion),
		slog.Int("packages", len(hostData.Packages)),
	)

	// Call Vulners API
	auditResult, err := s.vulnersClient.Audit().LinuxAudit(ctx, hostData.OSName, hostData.OSVersion, hostData.Packages)
	if err != nil {
		return nil, fmt.Errorf("vulners audit failed: %w", err)
	}

	// Extract vulnerable packages
	vulnPackages := extractVulnPackages(auditResult)

	// Filter by minimum CVSS
	vulnPackages = FilterByMinCVSS(vulnPackages, s.cfg.Scan.MinCVSS)

	// Extract bulletins and filter by minimum CVSS
	bulletins := extractBulletins(auditResult)
	bulletins = FilterBulletinsByMinCVSS(bulletins, s.cfg.Scan.MinCVSS)

	entry := &HostEntry{
		HostID:        hostData.Host.HostID,
		Host:          hostData.Host.Host,
		Name:          hostData.Host.Name,
		OSName:        hostData.OSName,
		OSVersion:     hostData.OSVersion,
		Score:         auditResult.CVSSScore,
		CumulativeFix: strings.ReplaceAll(auditResult.CumulativeFix, ",", ""),
		Packages:      vulnPackages,
		Bulletins:     bulletins,
	}

	span.SetAttributes(attribute.Float64("cvss.score", entry.Score))

	s.log.Info("Host scanned",
		slog.String("host", hostData.Host.Name),
		slog.Float64("score", entry.Score),
		slog.Int("packages", len(vulnPackages)),
		slog.Int("bulletins", len(bulletins)),
	)

	return entry, nil
}

// PushResults pushes scan results to Zabbix
func (s *Scanner) PushResults(ctx context.Context, results *ScanResults) error {
	_, span := telemetry.Tracer().Start(ctx, "Scanner.PushResults")
	defer span.End()

	span.SetAttributes(
		attribute.Int("hosts", len(results.Hosts)),
		attribute.Int("packages", len(results.Packages)),
		attribute.Int("bulletins", len(results.Bulletins)),
	)

	s.log.Info("Pushing LLD data to Zabbix...")

	// Generate and send hosts LLD
	hostsLLD := s.lldGenerator.GenerateHostsLLD(results.Hosts)
	if err := s.sender.SendLLD(s.cfg.Naming.HostsHost, "vulners.hosts_lld", hostsLLD); err != nil {
		return fmt.Errorf("failed to send hosts LLD: %w", err)
	}

	// Generate and send packages LLD
	packagesLLD := s.lldGenerator.GeneratePackagesLLD(results.Packages)
	if err := s.sender.SendLLD(s.cfg.Naming.PackagesHost, "vulners.packages_lld", packagesLLD); err != nil {
		return fmt.Errorf("failed to send packages LLD: %w", err)
	}

	// Generate and send bulletins LLD
	bulletinsLLD := s.lldGenerator.GenerateBulletinsLLD(results.Bulletins)
	if err := s.sender.SendLLD(s.cfg.Naming.BulletinsHost, "vulners.bulletins_lld", bulletinsLLD); err != nil {
		return fmt.Errorf("failed to send bulletins LLD: %w", err)
	}

	// Wait for Zabbix to process LLD and create discovered items
	if s.cfg.Scan.LLDDelay > 0 {
		s.log.Info("Waiting for Zabbix to process LLD rules...", slog.Int("seconds", s.cfg.Scan.LLDDelay))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(s.cfg.Scan.LLDDelay) * time.Second):
		}
	}

	s.log.Info("Pushing score data to Zabbix...")

	// Generate and send host scores
	hostScores := s.lldGenerator.GenerateHostScoreData(results.Hosts)
	if err := s.sender.SendBatch(hostScores); err != nil {
		return fmt.Errorf("failed to send host scores: %w", err)
	}

	// Generate and send package scores
	packageScores := s.lldGenerator.GeneratePackageScoreData(results.Packages)
	if err := s.sender.SendBatch(packageScores); err != nil {
		return fmt.Errorf("failed to send package scores: %w", err)
	}

	// Generate and send bulletin scores
	bulletinScores := s.lldGenerator.GenerateBulletinScoreData(results.Bulletins)
	if err := s.sender.SendBatch(bulletinScores); err != nil {
		return fmt.Errorf("failed to send bulletin scores: %w", err)
	}

	// Generate and send statistics
	stats := s.aggregator.GetStatistics()
	statsData := s.lldGenerator.GenerateStatisticsData(stats)
	if err := s.sender.SendBatch(statsData); err != nil {
		return fmt.Errorf("failed to send statistics: %w", err)
	}

	s.log.Info("Results pushed to Zabbix",
		slog.Int("hosts", len(results.Hosts)),
		slog.Int("packages", len(results.Packages)),
		slog.Int("bulletins", len(results.Bulletins)),
	)

	return nil
}

// GetAggregator returns the scanner's aggregator for external access
func (s *Scanner) GetAggregator() *Aggregator {
	return s.aggregator
}

// Close releases resources
func (s *Scanner) Close() error {
	return s.zabbixClient.Close()
}
