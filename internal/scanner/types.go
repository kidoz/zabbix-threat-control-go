package scanner

// ScanOptions configures a vulnerability scan
type ScanOptions struct {
	Limit   int      // Maximum number of hosts to scan (0 = unlimited)
	NoPush  bool     // Don't push results to Zabbix
	DryRun  bool     // Don't make any changes
	HostIDs []string // Specific host IDs to scan (empty = all)
}

// ScanResults contains the results of a vulnerability scan
type ScanResults struct {
	HostsScanned       int
	HostsWithVulns     int
	VulnerablePackages int
	MaxCVSS            float64
	Hosts              []HostEntry
	Packages           []PackageEntry
	Bulletins          []BulletinEntry
}

// HostEntry represents vulnerability data for a single host
type HostEntry struct {
	HostID        string
	Host          string // technical name
	Name          string // visible name
	OSName        string
	OSVersion     string
	Score         float64
	CumulativeFix string
	Packages      []PackageVuln
	Bulletins     []BulletinSummary
}

// PackageVuln represents vulnerability information for a single package
type PackageVuln struct {
	Name      string
	Version   string
	Arch      string
	Score     float64
	Fix       string
	Bulletins []string
	CVEs      []string
}

// BulletinSummary represents aggregated bulletin information
type BulletinSummary struct {
	ID            string
	Type          string
	Score         float64
	CVEs          []string
	Fix           string
	AffectedPkg   []string
	AffectedHosts []string
}

// PackageEntry represents a vulnerable package aggregated across hosts
type PackageEntry struct {
	Name              string
	Version           string
	Arch              string
	Score             float64
	Fix               string
	AffectedHosts     []string // host IDs
	AffectedHostNames []string // visible host names
	Bulletins         []string
}

// BulletinEntry represents a security bulletin aggregated across hosts
type BulletinEntry struct {
	ID                string
	Type              string
	Score             float64
	CVEs              []string
	Fix               string
	AffectedPkgs      []string
	AffectedHosts     []string // host IDs
	AffectedHostNames []string // visible host names
}

// Statistics contains aggregated statistics
type Statistics struct {
	TotalHosts      int
	VulnerableHosts int
	TotalPackages   int
	TotalBulletins  int
	TotalCVEs       int
	MaxCVSS         float64
	AvgCVSS         float64
	MinCVSS         float64
	MedianCVSS      float64
	Histogram       [11]int // index 0-10: count of hosts per integer CVSS score bucket
}
