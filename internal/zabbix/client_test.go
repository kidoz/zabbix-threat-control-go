package zabbix

import (
	"testing"
)

func TestGetAPIVersionFloat(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    float64
	}{
		{"standard 3-part", "6.4.1", 6.4},
		{"two-part", "5.4", 5.4},
		{"patch zero", "7.0.0", 7.0},
		{"old version", "5.0.3", 5.0},
		{"single part", "6", 0},
		{"empty", "", 0},
		{"alpha chars", "abc.def", 0},
		{"new major", "7.2.5", 7.2},
		{"double digit minor", "6.12.1", 6.12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{apiVersion: tt.version}
			got := c.getAPIVersionFloat()
			if got != tt.want {
				t.Errorf("getAPIVersionFloat(%q) = %f, want %f", tt.version, got, tt.want)
			}
		})
	}
}

func TestGetAPIVersionFloat_BranchingLogic(t *testing.T) {
	// Verify the version thresholds used in dashboard.go are correct
	tests := []struct {
		name       string
		version    string
		wantLegacy bool // < 5.4 = legacy trigger syntax
		wantTG     bool // >= 6.2 = templategroup API
	}{
		{"zabbix 5.0", "5.0.3", true, false},
		{"zabbix 5.2", "5.2.7", true, false},
		{"zabbix 5.4", "5.4.0", false, false},
		{"zabbix 6.0", "6.0.10", false, false},
		{"zabbix 6.2", "6.2.0", false, true},
		{"zabbix 6.4", "6.4.1", false, true},
		{"zabbix 7.0", "7.0.0", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{apiVersion: tt.version}
			v := c.getAPIVersionFloat()

			gotLegacy := v < 5.4
			if gotLegacy != tt.wantLegacy {
				t.Errorf("legacy trigger syntax: got %v, want %v (version=%f)", gotLegacy, tt.wantLegacy, v)
			}

			gotTG := v >= 6.2
			if gotTG != tt.wantTG {
				t.Errorf("templategroup API: got %v, want %v (version=%f)", gotTG, tt.wantTG, v)
			}
		})
	}
}
