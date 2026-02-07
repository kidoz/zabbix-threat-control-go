package scanner

import "testing"

func TestParseOSInfo(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"Ubuntu 20.04.3 LTS", "ubuntu", "20.04.3"},
		{"Red Hat Enterprise Linux Server release 7.9", "red hat enterprise linux server release", "7.9"},
		{"Debian GNU/Linux 11 (bullseye)", "debian gnu/linux", "11"},
		{"", "", ""},
		{"Alpine", "alpine", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version := parseOSInfo(tt.input)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

func TestParsePackageList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{"empty", "", 0},
		{"single line", "nginx 1.18.0 amd64", 1},
		{"multiple lines", "nginx 1.18.0 amd64\nopenssl 1.1.1k amd64\nbash 5.1 amd64", 3},
		{"blank lines", "nginx 1.18.0 amd64\n\n\nopenssl 1.1.1k amd64\n", 2},
		{"whitespace-only lines", "  \n\t\n  nginx 1.18.0 amd64  \n  ", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePackageList(tt.input)
			if len(got) != tt.wantLen {
				t.Errorf("parsePackageList() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestValidateHostData(t *testing.T) {
	// Helper: generate a slice of n dummy packages
	makePkgs := func(n int) []string {
		pkgs := make([]string, n)
		for i := range pkgs {
			pkgs[i] = "pkg" + string(rune('A'+i))
		}
		return pkgs
	}

	tests := []struct {
		name      string
		osVersion string
		packages  []string
		wantEmpty bool // true = valid (no reason)
	}{
		{"valid host", "20.04", makePkgs(10), true},
		{"os version 0.0 excluded", "0.0", makePkgs(10), false},
		{"exactly 5 packages excluded", "20.04", makePkgs(5), false},
		{"4 packages excluded", "20.04", makePkgs(4), false},
		{"6 packages valid", "20.04", makePkgs(6), true},
		{"report.py in packages excluded", "20.04", append(makePkgs(6), "report.py 1.0 noarch"), false},
		{"empty packages excluded", "20.04", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := validateHostData(tt.osVersion, tt.packages)
			if tt.wantEmpty && reason != "" {
				t.Errorf("expected valid (empty reason), got %q", reason)
			}
			if !tt.wantEmpty && reason == "" {
				t.Error("expected exclusion reason, got empty")
			}
		})
	}
}
