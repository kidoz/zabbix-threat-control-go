package fixer

import (
	"testing"
)

func TestValidateHostTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"valid IPv4", "192.168.1.1", false},
		{"valid IPv6", "2001:db8::1", false},
		{"loopback IPv6", "::1", false},
		{"valid FQDN", "web.example.com", false},
		{"valid short hostname", "myhost", false},
		{"valid subdomain", "db-01.prod.example.com", false},
		{"injection attempt IP", "192.168.1.1; rm -rf /", true},
		{"injection attempt hostname", "host;rm -rf /", true},
		{"empty", "", true},
		{"consecutive dots", "host..example.com", true},
		{"starts with dot", ".example.com", true},
		{"starts with hyphen", "-example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHostTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostTarget(%q) error = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePackageName(t *testing.T) {
	tests := []struct {
		name    string
		pkg     string
		wantErr bool
	}{
		{"nginx", "nginx", false},
		{"with arch", "libc6:amd64", false},
		{"with devel suffix", "kernel-devel", false},
		{"python version", "python3.11", false},
		{"with tilde", "pkg~beta1", false},
		{"with plus", "g++", false},
		{"injection attempt", "$(whoami)", true},
		{"spaces", "nginx openssl", true},
		{"empty", "", true},
		{"semicolon", "nginx;rm", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePackageName(tt.pkg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePackageName(%q) error = %v, wantErr %v", tt.pkg, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSSHUser(t *testing.T) {
	tests := []struct {
		name    string
		user    string
		wantErr bool
	}{
		{"root", "root", false},
		{"zabbix_user", "zabbix_user", false},
		{"user-name", "user-name", false},
		{"_service", "_service", false},
		{"injection attempt", "root; whoami", true},
		{"digit start", "1user", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSSHUser(tt.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSSHUser(%q) error = %v, wantErr %v", tt.user, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizePackages(t *testing.T) {
	t.Run("valid packages", func(t *testing.T) {
		err := SanitizePackages([]string{"nginx", "openssl", "libc6:amd64"})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("nil packages", func(t *testing.T) {
		err := SanitizePackages(nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid package", func(t *testing.T) {
		err := SanitizePackages([]string{"nginx", "$(bad)", "openssl"})
		if err == nil {
			t.Error("expected error for invalid package name")
		}
	})
}
