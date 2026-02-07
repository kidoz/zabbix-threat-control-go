package fixer

import (
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
)

func newTestExecutor() *Executor {
	return NewExecutor(config.DefaultConfig(), zap.NewNop())
}

func TestGenerateFixCommand(t *testing.T) {
	e := newTestExecutor()

	tests := []struct {
		name     string
		osName   string
		packages []string
		contains string // substring expected in the command
	}{
		{"ubuntu routes to apt", "Ubuntu 20.04", []string{"nginx"}, "apt-get"},
		{"debian routes to apt", "Debian GNU/Linux", []string{"openssl"}, "apt-get"},
		{"centos routes to yum", "CentOS Linux 7", []string{"httpd"}, "yum"},
		{"rhel routes to yum", "RHEL 8", []string{"httpd"}, "yum"},
		{"amazon routes to yum", "Amazon Linux 2", []string{"httpd"}, "yum"},
		{"unknown defaults to apt", "Arch Linux", []string{"nginx"}, "apt-get"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := e.GenerateFixCommand(tt.osName, tt.packages)
			if !strings.Contains(cmd, tt.contains) {
				t.Errorf("GenerateFixCommand(%q, %v) = %q, want to contain %q",
					tt.osName, tt.packages, cmd, tt.contains)
			}
		})
	}
}

func TestGenerateDebianFixCommand(t *testing.T) {
	t.Run("nil packages = full upgrade", func(t *testing.T) {
		cmd := generateDebianFixCommand(nil)
		if cmd != "apt-get update && apt-get upgrade -y" {
			t.Errorf("got %q, want full upgrade command", cmd)
		}
	})

	t.Run("with packages = only-upgrade with quoted names", func(t *testing.T) {
		cmd := generateDebianFixCommand([]string{"nginx", "openssl"})
		if !strings.Contains(cmd, "--only-upgrade") {
			t.Errorf("got %q, want --only-upgrade", cmd)
		}
		if !strings.Contains(cmd, "'nginx'") {
			t.Errorf("got %q, want quoted package name 'nginx'", cmd)
		}
		if !strings.Contains(cmd, "'openssl'") {
			t.Errorf("got %q, want quoted package name 'openssl'", cmd)
		}
	})
}

func TestGenerateRHELFixCommand(t *testing.T) {
	t.Run("nil packages = full update", func(t *testing.T) {
		cmd := generateRHELFixCommand(nil)
		if cmd != "yum update -y" {
			t.Errorf("got %q, want yum update -y", cmd)
		}
	})

	t.Run("with packages", func(t *testing.T) {
		cmd := generateRHELFixCommand([]string{"httpd"})
		if !strings.Contains(cmd, "yum update -y") {
			t.Errorf("got %q, want yum update -y", cmd)
		}
		if !strings.Contains(cmd, "'httpd'") {
			t.Errorf("got %q, want quoted 'httpd'", cmd)
		}
	})
}

func TestGenerateAmazonFixCommand(t *testing.T) {
	t.Run("nil packages = full update", func(t *testing.T) {
		cmd := generateAmazonFixCommand(nil)
		if cmd != "yum update -y" {
			t.Errorf("got %q, want yum update -y", cmd)
		}
	})

	t.Run("with packages", func(t *testing.T) {
		cmd := generateAmazonFixCommand([]string{"curl"})
		if !strings.Contains(cmd, "'curl'") {
			t.Errorf("got %q, want quoted 'curl'", cmd)
		}
	})
}
