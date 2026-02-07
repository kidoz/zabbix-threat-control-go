package fixer

import (
	"testing"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
)

func TestAppendUniqueStr(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		s     string
		want  int // expected length
	}{
		{"add to empty", nil, "nginx", 1},
		{"add new", []string{"nginx"}, "curl", 2},
		{"skip duplicate", []string{"nginx", "curl"}, "nginx", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendUniqueStr(tt.slice, tt.s)
			if len(got) != tt.want {
				t.Errorf("appendUniqueStr(%v, %q) length = %d, want %d", tt.slice, tt.s, len(got), tt.want)
			}
		})
	}
}

func TestIsVirtualHost(t *testing.T) {
	f := &Fixer{
		cfg: &config.Config{
			Naming: config.NamingConfig{
				HostsHost:      "vulners.hosts",
				PackagesHost:   "vulners.packages",
				BulletinsHost:  "vulners.bulletins",
				StatisticsHost: "vulners.statistics",
			},
		},
	}

	tests := []struct {
		name string
		host string
		want bool
	}{
		{"hosts virtual host", "vulners.hosts", true},
		{"packages virtual host", "vulners.packages", true},
		{"bulletins virtual host", "vulners.bulletins", true},
		{"statistics virtual host", "vulners.statistics", true},
		{"real host", "webserver01", false},
		{"empty", "", false},
		{"partial match", "vulners", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.isVirtualHost(tt.host)
			if got != tt.want {
				t.Errorf("isVirtualHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}
