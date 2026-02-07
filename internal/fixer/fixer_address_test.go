package fixer

import (
	"testing"

	"go.uber.org/zap"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/zabbix"
)

func TestGetHostAddress_MainAgentIP(t *testing.T) {
	f := &Fixer{log: zap.NewNop(), cfg: config.DefaultConfig()}
	host := &zabbix.Host{
		Interfaces: []zabbix.HostInterface{
			{Type: "1", Main: "1", UseIP: "1", IP: "10.0.0.1", DNS: "web01.example.com", Port: "10050"},
		},
	}
	addr, port := f.getHostAddress(host)
	if addr != "10.0.0.1" {
		t.Errorf("addr = %q, want 10.0.0.1", addr)
	}
	if port != "10050" {
		t.Errorf("port = %q, want 10050", port)
	}
}

func TestGetHostAddress_MainAgentDNS(t *testing.T) {
	f := &Fixer{log: zap.NewNop(), cfg: config.DefaultConfig()}
	host := &zabbix.Host{
		Interfaces: []zabbix.HostInterface{
			{Type: "1", Main: "1", UseIP: "0", IP: "", DNS: "web01.example.com", Port: "10050"},
		},
	}
	addr, port := f.getHostAddress(host)
	if addr != "web01.example.com" {
		t.Errorf("addr = %q, want web01.example.com", addr)
	}
	if port != "10050" {
		t.Errorf("port = %q, want 10050", port)
	}
}

func TestGetHostAddress_FallbackToMainNonAgent(t *testing.T) {
	f := &Fixer{log: zap.NewNop(), cfg: config.DefaultConfig()}
	// Type "2" = SNMP, but main=1 → should be the fallback
	host := &zabbix.Host{
		Interfaces: []zabbix.HostInterface{
			{Type: "2", Main: "1", UseIP: "1", IP: "10.0.0.2", Port: "161"},
		},
	}
	addr, port := f.getHostAddress(host)
	if addr != "10.0.0.2" {
		t.Errorf("addr = %q, want 10.0.0.2", addr)
	}
	if port != "161" {
		t.Errorf("port = %q, want 161", port)
	}
}

func TestGetHostAddress_FallbackToAnyInterface(t *testing.T) {
	f := &Fixer{log: zap.NewNop(), cfg: config.DefaultConfig()}
	host := &zabbix.Host{
		Interfaces: []zabbix.HostInterface{
			{Type: "2", Main: "0", UseIP: "1", IP: "10.0.0.3", Port: "161"},
		},
	}
	addr, _ := f.getHostAddress(host)
	if addr != "10.0.0.3" {
		t.Errorf("addr = %q, want 10.0.0.3", addr)
	}
}

func TestGetHostAddress_PreferAgentOverSNMP(t *testing.T) {
	f := &Fixer{log: zap.NewNop(), cfg: config.DefaultConfig()}
	host := &zabbix.Host{
		Interfaces: []zabbix.HostInterface{
			{Type: "2", Main: "1", UseIP: "1", IP: "10.0.0.2", Port: "161"},
			{Type: "1", Main: "1", UseIP: "1", IP: "10.0.0.1", Port: "10050"},
		},
	}
	addr, port := f.getHostAddress(host)
	if addr != "10.0.0.1" {
		t.Errorf("addr = %q, want 10.0.0.1 (agent preferred)", addr)
	}
	if port != "10050" {
		t.Errorf("port = %q, want 10050", port)
	}
}

func TestGetHostAddress_NoInterfaces(t *testing.T) {
	f := &Fixer{log: zap.NewNop(), cfg: config.DefaultConfig()}
	host := &zabbix.Host{}
	addr, port := f.getHostAddress(host)
	if addr != "" {
		t.Errorf("addr = %q, want empty", addr)
	}
	if port != "" {
		t.Errorf("port = %q, want empty", port)
	}
}

func TestGetHostAddress_DNSFallbackLastResort(t *testing.T) {
	f := &Fixer{log: zap.NewNop(), cfg: config.DefaultConfig()}
	host := &zabbix.Host{
		Interfaces: []zabbix.HostInterface{
			{Type: "2", Main: "0", UseIP: "0", IP: "", DNS: "fallback.local", Port: "161"},
		},
	}
	addr, _ := f.getHostAddress(host)
	if addr != "fallback.local" {
		t.Errorf("addr = %q, want fallback.local", addr)
	}
}
