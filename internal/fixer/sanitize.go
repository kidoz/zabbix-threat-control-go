package fixer

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	packageNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+:~-]*$`)
	sshUserRe     = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9._-]*$`)
	// fqdnRe validates a hostname: starts and ends with alphanumeric, allows
	// dots and hyphens in between. Each label must be <=63 chars and the total
	// length must be <=253 chars. Validated further in isValidFQDN.
	fqdnRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
)

// ValidateHostTarget validates that the given string is a valid IP address or
// FQDN. This accepts both IPs and DNS hostnames for hosts that use DNS in
// their Zabbix interface configuration.
func ValidateHostTarget(target string) error {
	if target == "" {
		return fmt.Errorf("host target is empty")
	}
	// Accept valid IP addresses
	if net.ParseIP(target) != nil {
		return nil
	}
	// Accept valid FQDNs
	if isValidFQDN(target) {
		return nil
	}
	return fmt.Errorf("invalid host target (not a valid IP or hostname): %q", target)
}

// isValidFQDN checks if s is a valid fully-qualified domain name.
func isValidFQDN(s string) bool {
	if len(s) > 253 {
		return false
	}
	if !fqdnRe.MatchString(s) {
		return false
	}
	// Check each label
	labels := strings.Split(s, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
	}
	return true
}

// ValidatePackageName validates that a package name contains only safe characters.
func ValidatePackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name is empty")
	}
	if len(name) > 256 {
		return fmt.Errorf("package name too long: %d chars", len(name))
	}
	if !packageNameRe.MatchString(name) {
		return fmt.Errorf("invalid package name: %q", name)
	}
	return nil
}

// ValidateSSHUser validates that an SSH username contains only safe characters.
func ValidateSSHUser(user string) error {
	if user == "" {
		return fmt.Errorf("SSH user is empty")
	}
	if len(user) > 64 {
		return fmt.Errorf("SSH user too long: %d chars", len(user))
	}
	if !sshUserRe.MatchString(user) {
		return fmt.Errorf("invalid SSH user: %q", user)
	}
	return nil
}

// SanitizePackages validates all package names in the slice.
func SanitizePackages(packages []string) error {
	for _, pkg := range packages {
		if err := ValidatePackageName(pkg); err != nil {
			return err
		}
	}
	return nil
}
