package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	prepareTemplates    bool
	prepareVirtualHosts bool
	prepareDashboard    bool
	prepareActions      bool
	prepareAll          bool
	prepareForce        bool
	prepareUtils        bool // hidden: Python -u compat (no-op in Go)
)

var prepareCmd = &cobra.Command{
	Use:   "prepare",
	Short: "Prepare Zabbix objects for vulnerability monitoring",
	Long: `Create and configure Zabbix objects required for vulnerability monitoring.

This command can create:
- OS-Report template for package collection (-t)
- Virtual hosts for aggregated vulnerability data (-V)
- Dashboards for vulnerability visualization (-d)
- Actions: checked but require manual configuration in the Zabbix UI (-A)

When upgrading from the Python version, run with --force to recreate
templates and discovery rules with the new key schema.

NOTE: This command does not require a Vulners API key.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log := GetLogger()
		cfg := GetConfig()

		log.Info("Preparing Zabbix objects...")

		client, err := initZabbixClient(cfg, log)
		if err != nil {
			return fmt.Errorf("failed to connect to Zabbix: %w", err)
		}
		defer func() { _ = client.Close() }()

		// Default to all when no specific flags are given.
		// This matches the typical usage (Python: prepare.py -uvtd)
		// and avoids a silent no-op when migration docs say "run ztc prepare".
		noFlagsSet := !prepareAll && !prepareTemplates && !prepareVirtualHosts && !prepareDashboard && !prepareActions
		if noFlagsSet {
			log.Warn("No flags specified, defaulting to --all (create all Zabbix objects)")
		}
		if prepareAll || noFlagsSet {
			prepareTemplates = true
			prepareVirtualHosts = true
			prepareDashboard = true
			prepareActions = true
		}

		ctx := context.Background()

		if prepareForce {
			log.Warn("Force mode enabled — existing objects will be recreated")
		}

		if prepareTemplates {
			log.Info("Creating/updating OS-Report template...")
			if err := client.EnsureOSReportTemplateCtx(ctx, prepareForce); err != nil {
				return fmt.Errorf("failed to create template: %w", err)
			}
			log.Info("OS-Report template ready")
		}

		if prepareVirtualHosts {
			log.Info("Creating virtual hosts...")
			if err := client.EnsureVirtualHostsCtx(ctx, prepareForce); err != nil {
				return fmt.Errorf("failed to create virtual hosts: %w", err)
			}
			log.Info("Virtual hosts ready")
		}

		if prepareDashboard {
			log.Info("Creating dashboard...")
			if err := client.EnsureDashboardCtx(ctx, prepareForce); err != nil {
				return fmt.Errorf("failed to create dashboard: %w", err)
			}
			log.Info("Dashboard ready")
		}

		if prepareActions {
			log.Info("Checking actions...")
			if err := client.EnsureActionsCtx(ctx); err != nil {
				return fmt.Errorf("failed to check actions: %w", err)
			}
		}

		log.Info("Zabbix preparation complete")
		return nil
	},
}

func init() {
	prepareCmd.Flags().BoolVarP(&prepareAll, "all", "a", false, "create all Zabbix objects (default when no flags given)")
	prepareCmd.Flags().BoolVarP(&prepareTemplates, "templates", "t", false, "create/update OS-Report template")
	prepareCmd.Flags().BoolVarP(&prepareVirtualHosts, "virtual-hosts", "V", false, "create virtual hosts")
	prepareCmd.Flags().BoolVarP(&prepareDashboard, "dashboard", "d", false, "create dashboard")
	prepareCmd.Flags().BoolVarP(&prepareActions, "actions", "A", false, "check if actions exist (manual Zabbix UI setup required)")
	prepareCmd.Flags().BoolVarP(&prepareForce, "force", "f", false, "recreate existing objects (use after upgrade to fix key schema changes)")

	// Hidden Python-compat flags so "prepare -uvtd" doesn't fail.
	// -u (--utils): Python checked zabbix-sender/get paths; Go does this implicitly.
	prepareCmd.Flags().BoolVarP(&prepareUtils, "utils", "u", false, "check utility paths (accepted for Python compat, no-op)")
	_ = prepareCmd.Flags().MarkHidden("utils")

	rootCmd.AddCommand(prepareCmd)
}
