package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/kidoz/zabbix-threat-control-go/internal/fixer"
)

var (
	fixBulletinID string
	fixHostID     string
	fixHostName   string
	fixDryRun     bool
	fixUseSSH     bool
	fixSSHUser    string
	fixForce      bool
)

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Fix vulnerabilities on hosts (experimental)",
	Long: `Execute remediation commands to fix vulnerabilities on hosts.

EXPERIMENTAL: This command queries previously-stored scan data from Zabbix
to determine which packages to update. If no per-package data is available,
it falls back to a full system update. Use --dry-run to review the plan
before executing. Use --force to skip the confirmation prompt.

This command can fix vulnerabilities by:
- Installing package updates via Zabbix agent (default)
- Executing commands via SSH (--ssh)

NOTE: Unlike the Python version, which used Vulners-provided fix commands
(specific version pins), the Go version generates generic OS package manager
commands (apt-get install --only-upgrade / yum update) with package names
only. This always installs the latest available version from configured
repositories, which may differ from the Vulners-recommended version.

CAUTION: This command executes system commands on remote hosts.
Always review the remediation plan before executing.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		log := GetLogger()
		cfg := GetConfig()

		if fixBulletinID == "" && fixHostID == "" && fixHostName == "" {
			return fmt.Errorf("either --bulletin, --host, or --host-name must be specified")
		}

		if !fixForce && !fixDryRun {
			fmt.Fprintln(os.Stderr, "WARNING: The fix command is experimental and executes remote commands.")
			fmt.Fprintln(os.Stderr, "Use --dry-run to review the plan first, or --force to skip this check.")
			return fmt.Errorf("pass --force to proceed (or --dry-run to preview)")
		}

		log.Info("Preparing fix operation...")

		f, err := initFixer(cfg, log)
		if err != nil {
			return fmt.Errorf("failed to initialize fixer: %w", err)
		}
		defer func() { _ = f.Close() }()

		opts := fixer.FixOptions{
			BulletinID: fixBulletinID,
			HostID:     fixHostID,
			HostName:   fixHostName,
			DryRun:     fixDryRun,
			UseSSH:     fixUseSSH,
			SSHUser:    fixSSHUser,
		}

		plan, err := f.Plan(opts)
		if err != nil {
			return fmt.Errorf("failed to create fix plan: %w", err)
		}

		log.Info("Fix plan created",
			zap.Int("hosts", len(plan.Hosts)),
			zap.Int("packages", len(plan.Packages)),
		)

		if fixDryRun {
			log.Info("Dry run mode - showing plan without executing")
			for _, h := range plan.Hosts {
				fmt.Printf("Host: %s (%s)\n", h.Name, h.IP)
				fmt.Printf("  Packages: %d\n", len(h.Packages))
				fmt.Printf("  Command:  %s\n", h.Command)
			}
			return nil
		}

		log.Info("Executing fix plan...")
		results, err := f.Execute(plan, opts)
		if err != nil {
			return fmt.Errorf("fix execution failed: %w", err)
		}

		log.Info("Fix operation completed",
			zap.Int("successful", results.Successful),
			zap.Int("failed", results.Failed),
		)

		return nil
	},
}

func init() {
	fixCmd.Flags().StringVar(&fixBulletinID, "bulletin", "", "bulletin ID to fix")
	fixCmd.Flags().StringVar(&fixHostID, "host", "", "specific host ID to fix")
	fixCmd.Flags().StringVar(&fixHostName, "host-name", "", "host technical name to fix (resolved to host ID)")
	fixCmd.Flags().BoolVar(&fixDryRun, "dry-run", false, "show fix plan without executing")
	fixCmd.Flags().BoolVar(&fixUseSSH, "ssh", false, "use SSH instead of Zabbix agent")
	fixCmd.Flags().StringVar(&fixSSHUser, "ssh-user", "root", "SSH user for remote execution")
	fixCmd.Flags().BoolVar(&fixForce, "force", false, "skip experimental confirmation prompt")

	rootCmd.AddCommand(fixCmd)
}
