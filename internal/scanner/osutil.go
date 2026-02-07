package scanner

import (
	"strings"
)

// ParsePackageString parses a package string like "nginx 1.18.0 amd64"
func ParsePackageString(pkg string) (name, version, arch string) {
	parts := strings.Fields(pkg)
	switch len(parts) {
	case 3:
		return parts[0], parts[1], parts[2]
	case 2:
		return parts[0], parts[1], ""
	case 1:
		return parts[0], "", ""
	default:
		return pkg, "", ""
	}
}

// NormalizeOSName normalizes OS names to Vulners format
func NormalizeOSName(osName string) string {
	osName = strings.ToLower(osName)

	// Map common OS names to Vulners format
	switch {
	case strings.Contains(osName, "ubuntu"):
		return "ubuntu"
	case strings.Contains(osName, "debian"):
		return "debian"
	case strings.Contains(osName, "centos"):
		return "centos"
	case strings.Contains(osName, "red hat") || strings.Contains(osName, "rhel"):
		return "redhat"
	case strings.Contains(osName, "amazon"):
		return "amazon"
	case strings.Contains(osName, "oracle"):
		return "oraclelinux"
	case strings.Contains(osName, "suse"):
		return "suse"
	case strings.Contains(osName, "fedora"):
		return "fedora"
	case strings.Contains(osName, "alpine"):
		return "alpine"
	case strings.Contains(osName, "arch"):
		return "arch"
	default:
		return osName
	}
}

// ExtractOSVersion extracts the version number from an OS string
func ExtractOSVersion(osVersion string) string {
	// Handle version strings like "20.04", "20.04 LTS", "7.9.2009", etc.
	parts := strings.Fields(osVersion)
	if len(parts) > 0 {
		// Take the first part which should be the version number
		version := parts[0]
		// Handle major.minor format (e.g., "20.04" -> "20.04")
		// or major only (e.g., "7" -> "7")
		return version
	}
	return osVersion
}
