package scanner

import (
	"sort"
)

// Aggregator aggregates vulnerability data across hosts
type Aggregator struct {
	hosts     []HostEntry
	packages  map[string]*PackageEntry
	bulletins map[string]*BulletinEntry
}

// NewAggregator creates a new aggregator
func NewAggregator() *Aggregator {
	return &Aggregator{
		packages:  make(map[string]*PackageEntry),
		bulletins: make(map[string]*BulletinEntry),
	}
}

// Reset clears accumulated data for a fresh scan.
func (a *Aggregator) Reset() {
	a.hosts = nil
	a.packages = make(map[string]*PackageEntry)
	a.bulletins = make(map[string]*BulletinEntry)
}

// AddHost adds a host's vulnerability data to the aggregator
func (a *Aggregator) AddHost(entry HostEntry) {
	a.hosts = append(a.hosts, entry)

	// Aggregate packages (keyed by name|version|arch to avoid merging
	// different-arch packages with the same name+version).
	for _, pkg := range entry.Packages {
		key := pkg.Name + "|" + pkg.Version + "|" + pkg.Arch
		if _, exists := a.packages[key]; !exists {
			a.packages[key] = &PackageEntry{
				Name:    pkg.Name,
				Version: pkg.Version,
				Arch:    pkg.Arch,
				Score:   pkg.Score,
				Fix:     pkg.Fix,
			}
		}
		a.packages[key].AffectedHosts = appendUnique(a.packages[key].AffectedHosts, entry.HostID)
		a.packages[key].AffectedHostNames = appendUnique(a.packages[key].AffectedHostNames, entry.Name)
		a.packages[key].Bulletins = appendUniqueSlice(a.packages[key].Bulletins, pkg.Bulletins)

		// Update score if higher
		if pkg.Score > a.packages[key].Score {
			a.packages[key].Score = pkg.Score
		}
	}

	// Aggregate bulletins
	for _, bulletin := range entry.Bulletins {
		if _, exists := a.bulletins[bulletin.ID]; !exists {
			a.bulletins[bulletin.ID] = &BulletinEntry{
				ID:    bulletin.ID,
				Type:  bulletin.Type,
				Score: bulletin.Score,
				CVEs:  bulletin.CVEs,
				Fix:   bulletin.Fix,
			}
		}
		a.bulletins[bulletin.ID].AffectedHosts = appendUnique(a.bulletins[bulletin.ID].AffectedHosts, entry.HostID)
		a.bulletins[bulletin.ID].AffectedHostNames = appendUnique(a.bulletins[bulletin.ID].AffectedHostNames, entry.Name)
		a.bulletins[bulletin.ID].AffectedPkgs = appendUniqueSlice(a.bulletins[bulletin.ID].AffectedPkgs, bulletin.AffectedPkg)

		// Update score if higher
		if bulletin.Score > a.bulletins[bulletin.ID].Score {
			a.bulletins[bulletin.ID].Score = bulletin.Score
		}
	}
}

// GetResults returns the aggregated results
func (a *Aggregator) GetResults() *ScanResults {
	results := &ScanResults{
		HostsScanned: len(a.hosts),
		Hosts:        a.hosts,
	}

	// Count vulnerable hosts and find max CVSS
	for _, host := range a.hosts {
		if host.Score > 0 {
			results.HostsWithVulns++
		}
		if host.Score > results.MaxCVSS {
			results.MaxCVSS = host.Score
		}
	}

	// Convert packages map to slice
	for _, pkg := range a.packages {
		results.Packages = append(results.Packages, *pkg)
		results.VulnerablePackages++
	}

	// Sort packages by score (descending)
	sort.Slice(results.Packages, func(i, j int) bool {
		return results.Packages[i].Score > results.Packages[j].Score
	})

	// Convert bulletins map to slice
	for _, bulletin := range a.bulletins {
		results.Bulletins = append(results.Bulletins, *bulletin)
	}

	// Sort bulletins by score (descending)
	sort.Slice(results.Bulletins, func(i, j int) bool {
		return results.Bulletins[i].Score > results.Bulletins[j].Score
	})

	return results
}

// GetStatistics returns aggregated statistics
func (a *Aggregator) GetStatistics() Statistics {
	stats := Statistics{
		TotalHosts:     len(a.hosts),
		TotalPackages:  len(a.packages),
		TotalBulletins: len(a.bulletins),
	}

	cveSet := make(map[string]bool)
	var totalScore float64

	// Collect ALL host scores (including 0) — matching Python behavior.
	scores := make([]float64, 0, len(a.hosts))
	for _, host := range a.hosts {
		if host.Score > 0 {
			stats.VulnerableHosts++
		}
		totalScore += host.Score
		scores = append(scores, host.Score)

		if host.Score > stats.MaxCVSS {
			stats.MaxCVSS = host.Score
		}

		// Histogram: bucket by integer score (0-10)
		bucket := int(host.Score)
		if bucket > 10 {
			bucket = 10
		}
		if bucket < 0 {
			bucket = 0
		}
		stats.Histogram[bucket]++
	}

	// Count unique CVEs
	for _, bulletin := range a.bulletins {
		for _, cve := range bulletin.CVEs {
			cveSet[cve] = true
		}
	}
	stats.TotalCVEs = len(cveSet)

	// Calculate average, min, median over ALL hosts (matching Python).
	// Python uses score_list = [0] as fallback when empty → all zeros.
	if len(scores) > 0 {
		stats.AvgCVSS = totalScore / float64(len(scores))

		sort.Float64s(scores)
		stats.MinCVSS = scores[0]

		mid := len(scores) / 2
		if len(scores)%2 == 0 {
			stats.MedianCVSS = (scores[mid-1] + scores[mid]) / 2
		} else {
			stats.MedianCVSS = scores[mid]
		}
	}

	return stats
}

// appendUnique appends a value to a slice if it doesn't already exist
func appendUnique(slice []string, value string) []string {
	for _, v := range slice {
		if v == value {
			return slice
		}
	}
	return append(slice, value)
}

// appendUniqueSlice appends values from src to dst, skipping duplicates
func appendUniqueSlice(dst, src []string) []string {
	existing := make(map[string]bool)
	for _, v := range dst {
		existing[v] = true
	}
	for _, v := range src {
		if !existing[v] {
			dst = append(dst, v)
			existing[v] = true
		}
	}
	return dst
}

// FilterByMinCVSS returns packages with CVSS >= minScore
func FilterByMinCVSS(packages []PackageVuln, minScore float64) []PackageVuln {
	var filtered []PackageVuln
	for _, pkg := range packages {
		if pkg.Score >= minScore {
			filtered = append(filtered, pkg)
		}
	}
	return filtered
}

// FilterBulletinsByMinCVSS returns bulletins with CVSS >= minScore
func FilterBulletinsByMinCVSS(bulletins []BulletinSummary, minScore float64) []BulletinSummary {
	var filtered []BulletinSummary
	for _, b := range bulletins {
		if b.Score >= minScore {
			filtered = append(filtered, b)
		}
	}
	return filtered
}
