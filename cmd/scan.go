package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/kidoz/zabbix-threat-control-go/internal/scanner"
)

var (
	scanLimit   int
	scanNoPush  bool
	scanDryRun  bool
	scanHostIDs []string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan hosts for vulnerabilities",
	Long: `Scan Zabbix hosts for security vulnerabilities using the Vulners API.

This command:
1. Fetches hosts with OS-Report template from Zabbix
2. Retrieves installed packages for each host
3. Queries Vulners API for known vulnerabilities
4. Aggregates results and sends data back to Zabbix`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log := GetLogger()
		cfg := GetConfig()

		if err := cfg.ValidateVulnersKey(); err != nil {
			return err
		}

		log.Info("Starting vulnerability scan...")

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		opts := scanner.ScanOptions{
			Limit:   scanLimit,
			NoPush:  scanNoPush,
			DryRun:  scanDryRun,
			HostIDs: scanHostIDs,
		}

		s, err := initScanner(cfg, log)
		if err != nil {
			return fmt.Errorf("failed to initialize scanner: %w", err)
		}
		defer func() { _ = s.Close() }()

		results, err := s.Scan(ctx, opts)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		log.Info("Scan completed",
			zap.Int("hosts_scanned", results.HostsScanned),
			zap.Int("vulnerabilities_found", results.VulnerablePackages),
		)

		if !scanNoPush && !scanDryRun {
			log.Info("Pushing results to Zabbix...")
			if err := s.PushResults(ctx, results); err != nil {
				return fmt.Errorf("failed to push results: %w", err)
			}
			log.Info("Results pushed to Zabbix successfully")
		} else {
			log.Info("Skipping push to Zabbix (--nopush or --dry-run specified)")
		}

		return nil
	},
}

func init() {
	scanCmd.Flags().IntVar(&scanLimit, "limit", 0, "limit number of hosts to scan (0 = unlimited)")
	scanCmd.Flags().BoolVar(&scanNoPush, "nopush", false, "do not push results to Zabbix")
	scanCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, "dry run mode (implies --nopush)")
	scanCmd.Flags().StringSliceVar(&scanHostIDs, "hosts", nil, "specific host IDs to scan (comma-separated)")

	rootCmd.AddCommand(scanCmd)
}
