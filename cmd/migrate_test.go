package cmd

import (
	"strings"
	"testing"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
)

func TestYamlQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", `""`},
		{"simple", "hello", "hello"},
		{"contains colon", "http://localhost", `"http://localhost"`},
		{"leading space", " hello", `" hello"`},
		{"trailing space", "hello ", `"hello "`},
		{"double quote escaping", `say "hi"`, `"say \"hi\""`},
		{"no special chars", `path\to`, `path\to`},
		{"contains hash", "value#comment", `"value#comment"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := yamlQuote(tt.input)
			if got != tt.want {
				t.Errorf("yamlQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRenderYAML_LLDDelay(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Zabbix.APIUser = "Admin"
	cfg.Zabbix.APIPassword = "zabbix"

	t.Run("non-default lld_delay is written", func(t *testing.T) {
		cfg.Scan.LLDDelay = 120
		out, err := renderYAML(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "lld_delay: 120") {
			t.Errorf("expected lld_delay: 120 in output, got:\n%s", string(out))
		}
	})

	t.Run("default lld_delay is omitted", func(t *testing.T) {
		cfg.Scan.LLDDelay = 300 // default
		out, err := renderYAML(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "lld_delay") {
			t.Errorf("expected lld_delay to be omitted for default value, got:\n%s", string(out))
		}
	})
}
