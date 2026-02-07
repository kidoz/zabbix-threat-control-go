package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Zabbix.FrontURL != "http://localhost" {
		t.Errorf("FrontURL = %q, want http://localhost", cfg.Zabbix.FrontURL)
	}
	if cfg.Zabbix.ServerPort != 10051 {
		t.Errorf("ServerPort = %d, want 10051", cfg.Zabbix.ServerPort)
	}
	if cfg.Zabbix.VerifySSL != true {
		t.Error("VerifySSL should default to true")
	}
	if cfg.Vulners.RateLimit != 10 {
		t.Errorf("RateLimit = %d, want 10", cfg.Vulners.RateLimit)
	}
	if cfg.Scan.MinCVSS != 1.0 {
		t.Errorf("MinCVSS = %f, want 1.0", cfg.Scan.MinCVSS)
	}
	if cfg.Scan.Workers != 4 {
		t.Errorf("Workers = %d, want 4", cfg.Scan.Workers)
	}
	if cfg.Scan.Timeout != 30 {
		t.Errorf("Timeout = %d, want 30", cfg.Scan.Timeout)
	}
	if cfg.Scan.OSReportTemplate != "tmpl.vulners.os-report" {
		t.Errorf("OSReportTemplate = %q, want tmpl.vulners.os-report", cfg.Scan.OSReportTemplate)
	}
	if cfg.Scan.OSReportVisibleName != "Template Vulners OS-Report" {
		t.Errorf("OSReportVisibleName = %q, want Template Vulners OS-Report", cfg.Scan.OSReportVisibleName)
	}
	if cfg.Scan.TemplateGroupName != "Templates" {
		t.Errorf("TemplateGroupName = %q, want Templates", cfg.Scan.TemplateGroupName)
	}
}

func TestValidate(t *testing.T) {
	validConfig := func() *Config {
		cfg := DefaultConfig()
		cfg.Vulners.APIKey = "test-key"
		cfg.Zabbix.APIUser = "admin"
		cfg.Zabbix.APIPassword = "password"
		return cfg
	}

	t.Run("valid config", func(t *testing.T) {
		cfg := validConfig()
		if err := cfg.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing api_key not checked by Validate", func(t *testing.T) {
		cfg := validConfig()
		cfg.Vulners.APIKey = ""
		// Validate() no longer requires vulners.api_key (only needed for scan/fix)
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate() should not fail on missing api_key: %v", err)
		}
	})

	t.Run("missing api_key checked by ValidateVulnersKey", func(t *testing.T) {
		cfg := validConfig()
		cfg.Vulners.APIKey = ""
		err := cfg.ValidateVulnersKey()
		if err == nil || !strings.Contains(err.Error(), "vulners.api_key") {
			t.Errorf("expected vulners.api_key error, got: %v", err)
		}
	})

	t.Run("missing api_user", func(t *testing.T) {
		cfg := validConfig()
		cfg.Zabbix.APIUser = ""
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "zabbix.api_user") {
			t.Errorf("expected zabbix.api_user error, got: %v", err)
		}
	})

	t.Run("missing api_password", func(t *testing.T) {
		cfg := validConfig()
		cfg.Zabbix.APIPassword = ""
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "zabbix.api_password") {
			t.Errorf("expected zabbix.api_password error, got: %v", err)
		}
	})

	t.Run("invalid server_port", func(t *testing.T) {
		cfg := validConfig()
		cfg.Zabbix.ServerPort = 0
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "server_port") {
			t.Errorf("expected server_port error, got: %v", err)
		}
	})

	t.Run("invalid server_port high", func(t *testing.T) {
		cfg := validConfig()
		cfg.Zabbix.ServerPort = 70000
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "server_port") {
			t.Errorf("expected server_port error, got: %v", err)
		}
	})

	t.Run("invalid front_url", func(t *testing.T) {
		cfg := validConfig()
		cfg.Zabbix.FrontURL = "not-a-url"
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "front_url") {
			t.Errorf("expected front_url error, got: %v", err)
		}
	})

	t.Run("invalid min_cvss negative", func(t *testing.T) {
		cfg := validConfig()
		cfg.Scan.MinCVSS = -1
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "min_cvss") {
			t.Errorf("expected min_cvss error, got: %v", err)
		}
	})

	t.Run("invalid min_cvss high", func(t *testing.T) {
		cfg := validConfig()
		cfg.Scan.MinCVSS = 11
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "min_cvss") {
			t.Errorf("expected min_cvss error, got: %v", err)
		}
	})

	t.Run("invalid workers", func(t *testing.T) {
		cfg := validConfig()
		cfg.Scan.Workers = 0
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "workers") {
			t.Errorf("expected workers error, got: %v", err)
		}
	})

	t.Run("invalid timeout", func(t *testing.T) {
		cfg := validConfig()
		cfg.Scan.Timeout = -1
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Errorf("expected timeout error, got: %v", err)
		}
	})

	t.Run("invalid rate_limit", func(t *testing.T) {
		cfg := validConfig()
		cfg.Vulners.RateLimit = -1
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "rate_limit") {
			t.Errorf("expected rate_limit error, got: %v", err)
		}
	})

	t.Run("multiple errors at once", func(t *testing.T) {
		cfg := DefaultConfig()
		// missing Zabbix required + bad port
		cfg.Zabbix.ServerPort = 0
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error")
		}
		errStr := err.Error()
		if !strings.Contains(errStr, "api_user") {
			t.Error("expected api_user error in combined output")
		}
		if !strings.Contains(errStr, "server_port") {
			t.Error("expected server_port error in combined output")
		}
	})
}

func TestDefaultConfig_LLDDelay(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Scan.LLDDelay != 300 {
		t.Errorf("LLDDelay = %d, want 300", cfg.Scan.LLDDelay)
	}
}

func TestLoadYAML_LLDDelay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	content := `
zabbix:
  front_url: "http://zabbix.example.com"
  api_user: admin
  api_password: secret
  server_port: 10051
vulners:
  api_key: test-api-key
scan:
  lld_delay: 120
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Scan.LLDDelay != 120 {
		t.Errorf("LLDDelay = %d, want 120", cfg.Scan.LLDDelay)
	}
}

func TestLoadINI_LLDDelay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	content := `[MANDATORY]
VulnersApiKey = test-key
ZabbixApiUser = admin
ZabbixApiPassword = secret

[OPTIONAL]
ZabbixFrontUrl = http://zabbix.local
ZabbixServerPort = 10051

[ADVANCED]
LLDDelay = 60
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Scan.LLDDelay != 60 {
		t.Errorf("LLDDelay = %d, want 60", cfg.Scan.LLDDelay)
	}
}

func TestLoadYAML_LLDDelay_Default(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	content := `
zabbix:
  front_url: "http://zabbix.example.com"
  api_user: admin
  api_password: secret
  server_port: 10051
vulners:
  api_key: test-api-key
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Scan.LLDDelay != 300 {
		t.Errorf("LLDDelay = %d, want 300 (default)", cfg.Scan.LLDDelay)
	}
}

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")

	content := `
zabbix:
  front_url: "http://zabbix.example.com"
  api_user: admin
  api_password: secret
  server_port: 10051
vulners:
  api_key: test-api-key
scan:
  min_cvss: 5.0
  workers: 8
  timeout: 60
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Zabbix.FrontURL != "http://zabbix.example.com" {
		t.Errorf("FrontURL = %q, want http://zabbix.example.com", cfg.Zabbix.FrontURL)
	}
	if cfg.Zabbix.APIUser != "admin" {
		t.Errorf("APIUser = %q, want admin", cfg.Zabbix.APIUser)
	}
	if cfg.Vulners.APIKey != "test-api-key" {
		t.Errorf("APIKey = %q, want test-api-key", cfg.Vulners.APIKey)
	}
	if cfg.Scan.MinCVSS != 5.0 {
		t.Errorf("MinCVSS = %f, want 5.0", cfg.Scan.MinCVSS)
	}
	if cfg.Scan.Workers != 8 {
		t.Errorf("Workers = %d, want 8", cfg.Scan.Workers)
	}
	if cfg.Scan.Timeout != 60 {
		t.Errorf("Timeout = %d, want 60", cfg.Scan.Timeout)
	}
}

func TestLoadINI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	content := `[MANDATORY]
VulnersApiKey = test-ini-key
ZabbixApiUser = admin
ZabbixApiPassword = secret

[OPTIONAL]
ZabbixFrontUrl = http://zabbix.local
ZabbixServerPort = 10051
MinCVSS = 3.5
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Vulners.APIKey != "test-ini-key" {
		t.Errorf("APIKey = %q, want test-ini-key", cfg.Vulners.APIKey)
	}
	if cfg.Zabbix.APIUser != "admin" {
		t.Errorf("APIUser = %q, want admin", cfg.Zabbix.APIUser)
	}
	if cfg.Zabbix.FrontURL != "http://zabbix.local" {
		t.Errorf("FrontURL = %q, want http://zabbix.local", cfg.Zabbix.FrontURL)
	}
	if cfg.Scan.MinCVSS != 3.5 {
		t.Errorf("MinCVSS = %f, want 3.5", cfg.Scan.MinCVSS)
	}
}

func TestINIToMap_UnrecognizedKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	content := `[MANDATORY]
VulnersApiKey = test-key
ZabbixApiUser = admin
ZabbixApiPassword = secret

[OPTIONAL]
ZabbixFrontUrl = http://zabbix.local
UnknownKey = some_value
AnotherBadKey = 123
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, warnings, err := LoadINIWithWarnings(path)
	if err != nil {
		t.Fatalf("LoadINIWithWarnings() error: %v", err)
	}

	// Known keys should still be parsed correctly
	if cfg.Vulners.APIKey != "test-key" {
		t.Errorf("APIKey = %q, want test-key", cfg.Vulners.APIKey)
	}
	if cfg.Zabbix.FrontURL != "http://zabbix.local" {
		t.Errorf("FrontURL = %q, want http://zabbix.local", cfg.Zabbix.FrontURL)
	}

	// Should have exactly 2 warnings for UnknownKey and AnotherBadKey
	if len(warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d: %v", len(warnings), warnings)
	}

	foundUnknown := false
	foundAnother := false
	for _, w := range warnings {
		if strings.Contains(w, "UnknownKey") && strings.Contains(w, "[OPTIONAL]") {
			foundUnknown = true
		}
		if strings.Contains(w, "AnotherBadKey") && strings.Contains(w, "[OPTIONAL]") {
			foundAnother = true
		}
	}
	if !foundUnknown {
		t.Errorf("expected warning for UnknownKey, got: %v", warnings)
	}
	if !foundAnother {
		t.Errorf("expected warning for AnotherBadKey, got: %v", warnings)
	}
}

func TestINIToMap_LegacyPythonKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	content := `[MANDATORY]
VulnersApiKey = test-key
ZabbixApiUser = admin
ZabbixApiPassword = secret

[OPTIONAL]
ZabbixFrontUrl = http://zabbix.local
VulnersProxyHost = proxy.internal
TrustedZabbixUsers = admin,operator
UseZabbixAgentToFix = 1
SSHUser = deploy
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, warnings, err := LoadINIWithWarnings(path)
	if err != nil {
		t.Fatalf("LoadINIWithWarnings() error: %v", err)
	}

	// Known keys should still parse correctly
	if cfg.Zabbix.FrontURL != "http://zabbix.local" {
		t.Errorf("FrontURL = %q, want http://zabbix.local", cfg.Zabbix.FrontURL)
	}

	// Should have 4 legacy-key warnings
	if len(warnings) != 4 {
		t.Fatalf("expected 4 legacy warnings, got %d: %v", len(warnings), warnings)
	}

	for _, w := range warnings {
		if !strings.Contains(w, "Python-only") {
			t.Errorf("expected 'Python-only' in warning, got: %s", w)
		}
	}
}

func TestINIToMap_NoWarningsForKnownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	content := `[MANDATORY]
VulnersApiKey = test-key
ZabbixApiUser = admin
ZabbixApiPassword = secret

[OPTIONAL]
ZabbixFrontUrl = http://zabbix.local
MinCVSS = 5.0
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	_, warnings, err := LoadINIWithWarnings(path)
	if err != nil {
		t.Fatalf("LoadINIWithWarnings() error: %v", err)
	}

	if len(warnings) != 0 {
		t.Errorf("expected 0 warnings for all-known keys, got %d: %v", len(warnings), warnings)
	}
}

func TestLoadINI_PythonKeyAliases(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	// Use the exact INI key names from the original Python config.py
	content := `[MANDATORY]
VulnersApiKey = test-key
ZabbixApiUser = admin
ZabbixApiPassword = secret

[OPTIONAL]
ZabbixFrontUrl = http://zabbix.local
ZabbixServerPort = 10051
VerifySSL = false
ZabbixSender = /usr/local/bin/zabbix_sender
ZabbixGet = /usr/local/bin/zabbix_get
TemplateHost = my.custom.template
TemplateVisibleName = My Custom Template
TemplateGroupName = Custom Templates
HostsHost = my.hosts
HostsVisibleName = My Hosts
DashboardName = My Dashboard
ActionName = My Action
HostGroupName = MyGroup
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// Python key aliases
	if cfg.Zabbix.VerifySSL != false {
		t.Error("VerifySSL: Python key 'VerifySSL' not mapped")
	}
	if cfg.Zabbix.SenderPath != "/usr/local/bin/zabbix_sender" {
		t.Errorf("SenderPath = %q; Python key 'ZabbixSender' not mapped", cfg.Zabbix.SenderPath)
	}
	if cfg.Zabbix.GetPath != "/usr/local/bin/zabbix_get" {
		t.Errorf("GetPath = %q; Python key 'ZabbixGet' not mapped", cfg.Zabbix.GetPath)
	}
	if cfg.Scan.OSReportTemplate != "my.custom.template" {
		t.Errorf("OSReportTemplate = %q; Python key 'TemplateHost' not mapped", cfg.Scan.OSReportTemplate)
	}
	if cfg.Scan.OSReportVisibleName != "My Custom Template" {
		t.Errorf("OSReportVisibleName = %q; Python key 'TemplateVisibleName' not mapped", cfg.Scan.OSReportVisibleName)
	}
	if cfg.Scan.TemplateGroupName != "Custom Templates" {
		t.Errorf("TemplateGroupName = %q; Python key 'TemplateGroupName' not mapped", cfg.Scan.TemplateGroupName)
	}
	// Naming keys
	if cfg.Naming.HostsHost != "my.hosts" {
		t.Errorf("HostsHost = %q", cfg.Naming.HostsHost)
	}
	if cfg.Naming.HostsVisibleName != "My Hosts" {
		t.Errorf("HostsVisibleName = %q", cfg.Naming.HostsVisibleName)
	}
	if cfg.Naming.DashboardName != "My Dashboard" {
		t.Errorf("DashboardName = %q", cfg.Naming.DashboardName)
	}
	if cfg.Naming.ActionName != "My Action" {
		t.Errorf("ActionName = %q", cfg.Naming.ActionName)
	}
	if cfg.Naming.GroupName != "MyGroup" {
		t.Errorf("GroupName = %q", cfg.Naming.GroupName)
	}
}
