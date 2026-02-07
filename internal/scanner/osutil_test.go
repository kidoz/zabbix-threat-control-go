package scanner

import (
	"testing"
)

func TestParsePackageString(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
		wantArch    string
	}{
		{"nginx 1.18.0 amd64", "nginx", "1.18.0", "amd64"},
		{"openssl 1.1.1k", "openssl", "1.1.1k", ""},
		{"bash", "bash", "", ""},
		{"", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version, arch := ParsePackageString(tt.input)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
			if arch != tt.wantArch {
				t.Errorf("arch = %q, want %q", arch, tt.wantArch)
			}
		})
	}
}

func TestNormalizeOSName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Ubuntu 20.04", "ubuntu"},
		{"ubuntu", "ubuntu"},
		{"Debian GNU/Linux", "debian"},
		{"CentOS Linux", "centos"},
		{"Red Hat Enterprise Linux", "redhat"},
		{"RHEL 8", "redhat"},
		{"Amazon Linux", "amazon"},
		{"Oracle Linux Server", "oraclelinux"},
		{"SUSE Linux Enterprise", "suse"},
		{"Fedora 35", "fedora"},
		{"Alpine Linux", "alpine"},
		{"unknown-os", "unknown-os"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeOSName(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeOSName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractOSVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"20.04", "20.04"},
		{"20.04 LTS", "20.04"},
		{"7.9.2009", "7.9.2009"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ExtractOSVersion(tt.input)
			if got != tt.want {
				t.Errorf("ExtractOSVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
