package fixer

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
)

// Executor executes fix commands on remote hosts
type Executor struct {
	cfg *config.Config
	log *zap.Logger
}

// NewExecutor creates a new executor
func NewExecutor(cfg *config.Config, log *zap.Logger) *Executor {
	return &Executor{
		cfg: cfg,
		log: log,
	}
}

// ExecuteViaAgent executes a command via Zabbix agent.
// The port parameter specifies the agent port (default "10050").
func (e *Executor) ExecuteViaAgent(ctx context.Context, hostIP, port, command string) (string, error) {
	if err := ValidateHostTarget(hostIP); err != nil {
		return "", fmt.Errorf("invalid host: %w", err)
	}

	if port == "" {
		port = "10050"
	}

	e.log.Debug("Executing command via Zabbix agent",
		zap.String("host", hostIP),
		zap.String("port", port),
		zap.String("command", command),
	)

	// Use zabbix_get to execute the command
	// Note: This requires the host to have system.run enabled in agent config.
	// Use nowait mode so long-running updates don't block/timeout the agent.
	key := fmt.Sprintf("system.run[%s,nowait]", command)

	cmd := exec.CommandContext(ctx, //nolint:gosec // G204: hostIP and command are validated by sanitize.go before reaching here
		e.cfg.Zabbix.GetPath,
		"-s", hostIP,
		"-p", port,
		"-k", key,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("zabbix_get failed: %w: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// ExecuteViaSSH executes a command via SSH
func (e *Executor) ExecuteViaSSH(ctx context.Context, hostIP, user, command string) (string, error) {
	if err := ValidateHostTarget(hostIP); err != nil {
		return "", fmt.Errorf("invalid host: %w", err)
	}
	if err := ValidateSSHUser(user); err != nil {
		return "", fmt.Errorf("invalid SSH user: %w", err)
	}

	e.log.Debug("Executing command via SSH",
		zap.String("host", hostIP),
		zap.String("user", user),
		zap.String("command", command),
	)

	cmd := exec.CommandContext(ctx, //nolint:gosec // G204: hostIP and user are validated by sanitize.go before reaching here
		"ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		fmt.Sprintf("%s@%s", user, hostIP),
		command,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("SSH failed: %w: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// GenerateFixCommand generates the package fix command for a host
func (e *Executor) GenerateFixCommand(osName string, packages []string) string {
	if err := SanitizePackages(packages); err != nil {
		e.log.Warn("Invalid package name detected, falling back to full system update", zap.Error(err))
		packages = nil
	}

	osName = strings.ToLower(osName)

	switch {
	case strings.Contains(osName, "ubuntu") || strings.Contains(osName, "debian"):
		return generateDebianFixCommand(packages)
	case strings.Contains(osName, "centos") || strings.Contains(osName, "red hat") || strings.Contains(osName, "redhat") || strings.Contains(osName, "rhel"):
		return generateRHELFixCommand(packages)
	case strings.Contains(osName, "amazon"):
		return generateAmazonFixCommand(packages)
	default:
		// Default to apt for unknown distros
		return generateDebianFixCommand(packages)
	}
}

func generateDebianFixCommand(packages []string) string {
	if len(packages) == 0 {
		return "apt-get update && apt-get upgrade -y"
	}
	pkgList := quotePackages(packages)
	return fmt.Sprintf("apt-get update && apt-get install -y --only-upgrade %s", pkgList)
}

func generateRHELFixCommand(packages []string) string {
	if len(packages) == 0 {
		return "yum update -y"
	}
	pkgList := quotePackages(packages)
	return fmt.Sprintf("yum update -y %s", pkgList)
}

func generateAmazonFixCommand(packages []string) string {
	if len(packages) == 0 {
		return "yum update -y"
	}
	pkgList := quotePackages(packages)
	return fmt.Sprintf("yum update -y %s", pkgList)
}

// quotePackages wraps each package name in single quotes for defense-in-depth.
func quotePackages(packages []string) string {
	quoted := make([]string, len(packages))
	for i, pkg := range packages {
		quoted[i] = "'" + pkg + "'"
	}
	return strings.Join(quoted, " ")
}

// ExecuteWithRetry executes a command with retry logic
func (e *Executor) ExecuteWithRetry(ctx context.Context, fn func() (string, error), maxRetries int) (string, error) {
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		output, err := fn()
		if err == nil {
			return output, nil
		}
		lastErr = err

		if i < maxRetries {
			e.log.Warn("Command failed, retrying...", zap.Error(err), zap.Int("attempt", i+1))
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(i+1) * time.Second):
			}
		}
	}
	return "", lastErr
}
