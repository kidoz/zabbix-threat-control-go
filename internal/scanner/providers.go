package scanner

import (
	"fmt"
	"net/http"
	"time"

	"log/slog"

	vulners "github.com/kidoz/go-vulners"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.uber.org/fx"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/zabbix"
)

// Module provides all scanner dependencies for fx injection.
var Module = fx.Module("scanner",
	fx.Provide(
		ProvideScanner,
		NewHostMatrix,
		NewAggregator,
		ProvideNamingConfig,
		NewLLDGenerator,
		ProvideVulnersClient,
	),
	zabbix.Module,
)

// ProvideNamingConfig extracts the NamingConfig from Config for NewLLDGenerator.
func ProvideNamingConfig(cfg *config.Config) config.NamingConfig {
	return cfg.Naming
}

// ProvideVulnersClient creates a Vulners API client with OTel-instrumented HTTP transport.
func ProvideVulnersClient(cfg *config.Config) (*vulners.Client, error) {
	instrumentedHTTP := &http.Client{
		Timeout:   time.Duration(cfg.Scan.Timeout) * time.Second,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}

	client, err := vulners.NewClient(cfg.Vulners.APIKey,
		vulners.WithHTTPClient(instrumentedHTTP),
		vulners.WithRateLimit(float64(cfg.Vulners.RateLimit), cfg.Vulners.RateLimit*2),
		vulners.WithBaseURL(cfg.Vulners.Host),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vulners client: %w", err)
	}

	return client, nil
}

// ProvideScanner assembles a Scanner from its injected dependencies.
func ProvideScanner(
	cfg *config.Config,
	log *slog.Logger,
	zabbixClient *zabbix.Client,
	vulnersClient *vulners.Client,
	sender *zabbix.Sender,
	hostMatrix *HostMatrix,
	aggregator *Aggregator,
	lldGenerator *LLDGenerator,
) *Scanner {
	return &Scanner{
		cfg:           cfg,
		log:           log,
		zabbixClient:  zabbixClient,
		vulnersClient: vulnersClient,
		sender:        sender,
		hostMatrix:    hostMatrix,
		aggregator:    aggregator,
		lldGenerator:  lldGenerator,
	}
}
