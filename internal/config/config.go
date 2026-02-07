package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"gopkg.in/ini.v1"
)

// DefaultConfigPath is the default config path, matching the original Python project.
const DefaultConfigPath = "/opt/monitoring/zabbix-threat-control/ztc.conf"

// configSearchPaths lists config file paths to try, in priority order.
var configSearchPaths = []string{
	"/opt/monitoring/zabbix-threat-control/ztc.conf", // legacy INI (Python project)
	"/etc/ztc.yaml", // new YAML
	"/etc/ztc.conf", // alternate legacy INI
}

// FindConfigPath returns the first existing config file from the search paths.
// If none exist, it returns DefaultConfigPath (which will fail with a clear error).
func FindConfigPath() string {
	for _, path := range configSearchPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return DefaultConfigPath
}

// Config holds all configuration values for ZTC
type Config struct {
	Zabbix    ZabbixConfig    `koanf:"zabbix"`
	Vulners   VulnersConfig   `koanf:"vulners"`
	Scan      ScanConfig      `koanf:"scan"`
	Telemetry TelemetryConfig `koanf:"telemetry"`
	Naming    NamingConfig    `koanf:"naming"`
}

// NamingConfig holds customizable names for virtual hosts, groups, dashboards, and actions.
// These match the [OPTIONAL] section keys in the original Python config.
type NamingConfig struct {
	HostsHost             string `koanf:"hosts_host"`
	HostsVisibleName      string `koanf:"hosts_visible_name"`
	PackagesHost          string `koanf:"packages_host"`
	PackagesVisibleName   string `koanf:"packages_visible_name"`
	BulletinsHost         string `koanf:"bulletins_host"`
	BulletinsVisibleName  string `koanf:"bulletins_visible_name"`
	StatisticsHost        string `koanf:"statistics_host"`
	StatisticsVisibleName string `koanf:"statistics_visible_name"`
	GroupName             string `koanf:"group_name"`
	DashboardName         string `koanf:"dashboard_name"`
	ActionName            string `koanf:"action_name"`
}

// ZabbixConfig holds Zabbix connection settings
type ZabbixConfig struct {
	FrontURL    string `koanf:"front_url"`
	APIUser     string `koanf:"api_user"`
	APIPassword string `koanf:"api_password"`
	ServerFQDN  string `koanf:"server_fqdn"`
	ServerPort  int    `koanf:"server_port"`
	SenderPath  string `koanf:"sender_path"`
	GetPath     string `koanf:"get_path"`
	VerifySSL   bool   `koanf:"verify_ssl"`
}

// VulnersConfig holds Vulners API settings
type VulnersConfig struct {
	APIKey    string `koanf:"api_key"`
	Host      string `koanf:"host"`
	RateLimit int    `koanf:"rate_limit"`
}

// ScanConfig holds scanning parameters
type ScanConfig struct {
	MinCVSS             float64 `koanf:"min_cvss"`
	OSReportTemplate    string  `koanf:"os_report_template"`
	OSReportVisibleName string  `koanf:"os_report_visible_name"`
	TemplateGroupName   string  `koanf:"template_group_name"`
	Timeout             int     `koanf:"timeout"`
	Workers             int     `koanf:"workers"`
	LLDDelay            int     `koanf:"lld_delay"`
}

// TelemetryConfig holds OpenTelemetry settings
type TelemetryConfig struct {
	Enabled      bool   `koanf:"enabled"`
	OTLPEndpoint string `koanf:"otlp_endpoint"`
}

// DefaultConfig returns a Config with default values
func DefaultConfig() *Config {
	return &Config{
		Zabbix: ZabbixConfig{
			FrontURL:   "http://localhost",
			ServerFQDN: "localhost",
			ServerPort: 10051,
			SenderPath: "zabbix_sender",
			GetPath:    "zabbix_get",
			VerifySSL:  true,
		},
		Vulners: VulnersConfig{
			Host:      "https://vulners.com",
			RateLimit: 10,
		},
		Scan: ScanConfig{
			MinCVSS:             1.0,
			OSReportTemplate:    "tmpl.vulners.os-report",
			OSReportVisibleName: "Template Vulners OS-Report",
			TemplateGroupName:   "Templates",
			Timeout:             30,
			Workers:             4,
			LLDDelay:            300,
		},
		Telemetry: TelemetryConfig{
			Enabled: false,
		},
		Naming: NamingConfig{
			HostsHost:             "vulners.hosts",
			HostsVisibleName:      "Vulners - Hosts",
			PackagesHost:          "vulners.packages",
			PackagesVisibleName:   "Vulners - Packages",
			BulletinsHost:         "vulners.bulletins",
			BulletinsVisibleName:  "Vulners - Bulletins",
			StatisticsHost:        "vulners.statistics",
			StatisticsVisibleName: "Vulners - Statistics",
			GroupName:             "Vulners",
			DashboardName:         "Vulners",
			ActionName:            "Vulners",
		},
	}
}

// Load reads configuration from a file, auto-detecting format by extension.
// .yaml/.yml → YAML (Koanf), .conf/.ini or anything else → legacy INI.
// Environment variables (ZTC_ prefix) always override file values.
func Load(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".yaml", ".yml":
		return loadYAML(path)
	default:
		// .conf, .ini, or no extension → try INI (backwards compat)
		return loadINI(path)
	}
}

// loadYAML loads config from a YAML file with Koanf.
func loadYAML(path string) (*Config, error) {
	k := koanf.New(".")

	if err := loadDefaults(k); err != nil {
		return nil, err
	}

	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config file: %w", err)
	}

	if err := loadEnvOverrides(k); err != nil {
		return nil, err
	}

	return unmarshalAndValidate(k)
}

// loadINI loads config from a legacy INI file (backwards compatible with
// the original Python zabbix-threat-control project).
func loadINI(path string) (*Config, error) {
	iniFile, err := ini.Load(path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse INI config file: %w", err)
	}

	// Map INI sections/keys → flat koanf key map
	m, warnings := iniToMap(iniFile)
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "WARNING: %s\n", w)
	}

	k := koanf.New(".")

	if err := loadDefaults(k); err != nil {
		return nil, err
	}

	if err := k.Load(confmap.Provider(m, "."), nil); err != nil {
		return nil, fmt.Errorf("failed to load INI values: %w", err)
	}

	if err := loadEnvOverrides(k); err != nil {
		return nil, err
	}

	return unmarshalAndValidate(k)
}

// LoadINI is an exported variant for the migrate-config command.
// It reads a legacy INI file and returns a *Config without env overrides.
func LoadINI(path string) (*Config, error) {
	cfg, _, err := LoadINIWithWarnings(path)
	return cfg, err
}

// LoadINIWithWarnings is like LoadINI but also returns warnings for
// unrecognized INI keys that were skipped during parsing.
func LoadINIWithWarnings(path string) (*Config, []string, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("config file not found: %s", path)
	}

	iniFile, err := ini.Load(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse INI config file: %w", err)
	}

	m, warnings := iniToMap(iniFile)

	k := koanf.New(".")

	if err := loadDefaults(k); err != nil {
		return nil, nil, err
	}

	if err := k.Load(confmap.Provider(m, "."), nil); err != nil {
		return nil, nil, fmt.Errorf("failed to load INI values: %w", err)
	}

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, warnings, nil
}

// iniKeyMap maps INI key names (lowercased, no separators) to koanf key paths.
var iniKeyMap = map[string]string{
	// MANDATORY section
	"vulnersapikey":     "vulners.api_key",
	"zabbixapiuser":     "zabbix.api_user",
	"zabbixapipassword": "zabbix.api_password",
	// OPTIONAL section
	"zabbixfronturl":      "zabbix.front_url",
	"zabbixserverfqdn":    "zabbix.server_fqdn",
	"zabbixserverport":    "zabbix.server_port",
	"zabbixsenderpath":    "zabbix.sender_path", // Go alias
	"zabbixsender":        "zabbix.sender_path", // Python key: ZabbixSender
	"zabbixgetpath":       "zabbix.get_path",    // Go alias
	"zabbixget":           "zabbix.get_path",    // Python key: ZabbixGet
	"mincvss":             "scan.min_cvss",
	"osreporttemplate":    "scan.os_report_template",     // Go alias
	"templatehost":        "scan.os_report_template",     // Python key: TemplateHost
	"templatevisiblename": "scan.os_report_visible_name", // Python key: TemplateVisibleName
	"templategroupname":   "scan.template_group_name",    // Python key: TemplateGroupName
	// OPTIONAL section — naming
	"hostshost":             "naming.hosts_host",
	"hostsvisiblename":      "naming.hosts_visible_name",
	"packageshost":          "naming.packages_host",
	"packagesvisiblename":   "naming.packages_visible_name",
	"bulletinshost":         "naming.bulletins_host",
	"bulletinsvisiblename":  "naming.bulletins_visible_name",
	"statisticshost":        "naming.statistics_host",
	"statisticsvisiblename": "naming.statistics_visible_name",
	"hostgroupname":         "naming.group_name",
	"dashboardname":         "naming.dashboard_name",
	"actionname":            "naming.action_name",
	// ADVANCED section
	"zabbixverifyssl":  "zabbix.verify_ssl", // Go alias
	"verifyssl":        "zabbix.verify_ssl", // Python key: VerifySSL
	"vulnershost":      "vulners.host",
	"vulnersratelimit": "vulners.rate_limit",
	"timeout":          "scan.timeout",
	"workers":          "scan.workers",
	"llddelay":         "scan.lld_delay",
}

// legacyINIKeys lists Python-era INI keys that are recognized but have no
// Go equivalent. They produce a specific warning instead of "unrecognized".
var legacyINIKeys = map[string]bool{
	"vulnersproxyhost":        true, // proxy not implemented
	"vulnersproxyport":        true, // proxy not implemented
	"trustedzabbixusers":      true, // trust checks not implemented
	"usezabbixagenttofix":     true, // fix uses --ssh flag instead
	"sshuser":                 true, // fix uses --ssh-user flag instead
	"logfile":                 true, // Go uses stdout/stderr
	"debuglevel":              true, // Go uses --verbose flag
	"workdir":                 true, // not needed in Go
	"hostsapplicationname":    true, // Zabbix < 5.2 concept, deprecated
	"statisticsmacrosname":    true, // hardcoded in Go
	"statisticsmacrosvalue":   true, // hardcoded in Go
	"templatemacrosname":      true, // hardcoded in Go
	"templatemacrosvalue":     true, // hardcoded in Go
	"templateapplicationname": true, // Zabbix < 5.2 concept, deprecated
}

// iniToMap maps legacy INI section/key names to the nested koanf key namespace.
// It returns the mapped values and a slice of warnings for unrecognized keys.
func iniToMap(f *ini.File) (map[string]interface{}, []string) {
	m := make(map[string]interface{})
	var warnings []string

	for _, section := range f.Sections() {
		for _, key := range section.Keys() {
			normalised := strings.ToLower(key.Name())
			if koanfKey, ok := iniKeyMap[normalised]; ok {
				m[koanfKey] = key.Value()
			} else if legacyINIKeys[normalised] {
				warnings = append(warnings, fmt.Sprintf("Python-only INI key [%s] %s is not supported in the Go version (skipped)", section.Name(), key.Name()))
			} else if section.Name() != "DEFAULT" {
				warnings = append(warnings, fmt.Sprintf("unrecognized INI key [%s] %s (skipped)", section.Name(), key.Name()))
			}
		}
	}

	return m, warnings
}

// --- helpers ---

func loadDefaults(k *koanf.Koanf) error {
	defaults := DefaultConfig()
	return k.Load(confmap.Provider(map[string]interface{}{
		"zabbix.front_url":               defaults.Zabbix.FrontURL,
		"zabbix.server_fqdn":             defaults.Zabbix.ServerFQDN,
		"zabbix.server_port":             defaults.Zabbix.ServerPort,
		"zabbix.sender_path":             defaults.Zabbix.SenderPath,
		"zabbix.get_path":                defaults.Zabbix.GetPath,
		"zabbix.verify_ssl":              defaults.Zabbix.VerifySSL,
		"vulners.host":                   defaults.Vulners.Host,
		"vulners.rate_limit":             defaults.Vulners.RateLimit,
		"scan.min_cvss":                  defaults.Scan.MinCVSS,
		"scan.os_report_template":        defaults.Scan.OSReportTemplate,
		"scan.os_report_visible_name":    defaults.Scan.OSReportVisibleName,
		"scan.template_group_name":       defaults.Scan.TemplateGroupName,
		"scan.timeout":                   defaults.Scan.Timeout,
		"scan.workers":                   defaults.Scan.Workers,
		"scan.lld_delay":                 defaults.Scan.LLDDelay,
		"telemetry.enabled":              defaults.Telemetry.Enabled,
		"naming.hosts_host":              defaults.Naming.HostsHost,
		"naming.hosts_visible_name":      defaults.Naming.HostsVisibleName,
		"naming.packages_host":           defaults.Naming.PackagesHost,
		"naming.packages_visible_name":   defaults.Naming.PackagesVisibleName,
		"naming.bulletins_host":          defaults.Naming.BulletinsHost,
		"naming.bulletins_visible_name":  defaults.Naming.BulletinsVisibleName,
		"naming.statistics_host":         defaults.Naming.StatisticsHost,
		"naming.statistics_visible_name": defaults.Naming.StatisticsVisibleName,
		"naming.group_name":              defaults.Naming.GroupName,
		"naming.dashboard_name":          defaults.Naming.DashboardName,
		"naming.action_name":             defaults.Naming.ActionName,
	}, "."), nil)
}

func loadEnvOverrides(k *koanf.Koanf) error {
	// ZTC_ZABBIX_FRONT_URL → zabbix.front_url
	return k.Load(env.Provider("ZTC_", ".", func(s string) string {
		s = strings.TrimPrefix(s, "ZTC_")
		s = strings.ToLower(s)
		if idx := strings.Index(s, "_"); idx >= 0 {
			return s[:idx] + "." + s[idx+1:]
		}
		return s
	}), nil)
}

func unmarshalAndValidate(k *koanf.Koanf) (*Config, error) {
	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks that Zabbix connection fields are set and values are in range.
// It does NOT require vulners.api_key — that is only needed for scan/fix commands
// and is validated by ValidateVulnersKey().
func (c *Config) Validate() error {
	var errs []error

	// Zabbix connection (always required)
	if c.Zabbix.APIUser == "" {
		errs = append(errs, fmt.Errorf("zabbix.api_user is required"))
	}
	if c.Zabbix.APIPassword == "" {
		errs = append(errs, fmt.Errorf("zabbix.api_password is required"))
	}

	// Range checks
	if c.Zabbix.ServerPort < 1 || c.Zabbix.ServerPort > 65535 {
		errs = append(errs, fmt.Errorf("zabbix.server_port must be between 1 and 65535, got %d", c.Zabbix.ServerPort))
	}
	if c.Zabbix.FrontURL != "" {
		u, err := url.Parse(c.Zabbix.FrontURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			errs = append(errs, fmt.Errorf("zabbix.front_url must be a valid URL with scheme and host"))
		}
	}
	if c.Scan.MinCVSS < 0 || c.Scan.MinCVSS > 10 {
		errs = append(errs, fmt.Errorf("scan.min_cvss must be between 0.0 and 10.0, got %g", c.Scan.MinCVSS))
	}
	if c.Scan.Workers <= 0 {
		errs = append(errs, fmt.Errorf("scan.workers must be greater than 0, got %d", c.Scan.Workers))
	}
	if c.Scan.Timeout <= 0 {
		errs = append(errs, fmt.Errorf("scan.timeout must be greater than 0, got %d", c.Scan.Timeout))
	}
	if c.Vulners.RateLimit < 0 {
		errs = append(errs, fmt.Errorf("vulners.rate_limit must be >= 0, got %d", c.Vulners.RateLimit))
	}

	return errors.Join(errs...)
}

// ValidateVulnersKey checks that the Vulners API key is set.
// Call this in commands that need the Vulners API (scan, fix).
func (c *Config) ValidateVulnersKey() error {
	if c.Vulners.APIKey == "" {
		return fmt.Errorf("vulners.api_key is required (set in config file or ZTC_VULNERS_API_KEY env var)")
	}
	return nil
}

// ZabbixAPIURL returns the full Zabbix API URL
func (c *Config) ZabbixAPIURL() string {
	return strings.TrimRight(c.Zabbix.FrontURL, "/") + "/api_jsonrpc.php"
}
