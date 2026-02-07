package scanner

import (
	"fmt"
	"strings"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/zabbix"
)

// LLDGenerator generates Low-Level Discovery data for Zabbix
type LLDGenerator struct {
	naming config.NamingConfig
}

// NewLLDGenerator creates a new LLD generator
func NewLLDGenerator(naming config.NamingConfig) *LLDGenerator {
	return &LLDGenerator{naming: naming}
}

// GenerateHostsLLD generates LLD data for hosts
func (g *LLDGenerator) GenerateHostsLLD(hosts []HostEntry) *zabbix.LLDData {
	data := &zabbix.LLDData{
		Data: make([]map[string]interface{}, 0, len(hosts)),
	}

	for _, host := range hosts {
		entry := map[string]interface{}{
			"{#H.ID}":    host.HostID,
			"{#H.HOST}":  host.Host,
			"{#H.VNAME}": host.Name,
			"{#H.SCORE}": fmt.Sprintf("%.1f", host.Score),
			"{#H.OS}":    host.OSName,
			"{#H.OSVER}": host.OSVersion,
			"{#H.FIX}":   host.CumulativeFix,
		}
		data.Data = append(data.Data, entry)
	}

	return data
}

// GeneratePackagesLLD generates LLD data for packages
func (g *LLDGenerator) GeneratePackagesLLD(packages []PackageEntry) *zabbix.LLDData {
	data := &zabbix.LLDData{
		Data: make([]map[string]interface{}, 0, len(packages)),
	}

	for _, pkg := range packages {
		affected := len(pkg.AffectedHosts)
		impact := int(float64(affected) * pkg.Score)

		// First bulletin ID for vulners.com link
		pkgURL := ""
		if len(pkg.Bulletins) > 0 {
			pkgURL = pkg.Bulletins[0]
		}

		// Package ID matches Python's {#PKG.ID} format
		pkgID := fmt.Sprintf("%s %s %s", pkg.Name, pkg.Version, pkg.Arch)

		entry := map[string]interface{}{
			"{#P.NAME}":     pkg.Name,
			"{#P.VERSION}":  pkg.Version,
			"{#P.ARCH}":     pkg.Arch,
			"{#P.SCORE}":    fmt.Sprintf("%.1f", pkg.Score),
			"{#P.FIX}":      pkg.Fix,
			"{#P.AFFECTED}": affected,
			"{#P.HOSTS}":    strings.Join(pkg.AffectedHosts, ","),
			// Python-compatible trigger macros
			"{#PKG.ID}":     pkgID,
			"{#PKG.SCORE}":  fmt.Sprintf("%.1f", pkg.Score),
			"{#PKG.IMPACT}": impact,
			"{#PKG.URL}":    pkgURL,
			"{#PKG.HOSTS}":  strings.Join(pkg.AffectedHostNames, "\n"),
			"{#PKG.FIX}":    pkg.Fix,
		}
		data.Data = append(data.Data, entry)
	}

	return data
}

// GenerateBulletinsLLD generates LLD data for bulletins
func (g *LLDGenerator) GenerateBulletinsLLD(bulletins []BulletinEntry) *zabbix.LLDData {
	data := &zabbix.LLDData{
		Data: make([]map[string]interface{}, 0, len(bulletins)),
	}

	for _, bulletin := range bulletins {
		affected := len(bulletin.AffectedHosts)
		impact := int(float64(affected) * bulletin.Score)

		entry := map[string]interface{}{
			"{#B.ID}":       bulletin.ID,
			"{#B.TYPE}":     bulletin.Type,
			"{#B.SCORE}":    fmt.Sprintf("%.1f", bulletin.Score),
			"{#B.CVES}":     strings.Join(bulletin.CVEs, ","),
			"{#B.AFFECTED}": affected,
			"{#B.HOSTS}":    strings.Join(bulletin.AffectedHosts, ","),
			"{#B.PKGS}":     strings.Join(bulletin.AffectedPkgs, ","),
			// Python-compatible trigger macros
			"{#BULLETIN.ID}":     bulletin.ID,
			"{#BULLETIN.SCORE}":  fmt.Sprintf("%.1f", bulletin.Score),
			"{#BULLETIN.IMPACT}": impact,
			"{#BULLETIN.HOSTS}":  strings.Join(bulletin.AffectedHostNames, "\n"),
		}
		data.Data = append(data.Data, entry)
	}

	return data
}

// GenerateHostScoreData generates individual score data for each host
func (g *LLDGenerator) GenerateHostScoreData(hosts []HostEntry) []zabbix.SenderData {
	var data []zabbix.SenderData

	for _, host := range hosts {
		data = append(data, zabbix.SenderData{
			Host:  g.naming.HostsHost,
			Key:   fmt.Sprintf("vulners.hosts[%s]", host.HostID),
			Value: fmt.Sprintf("%.1f", host.Score),
		})
	}

	return data
}

// GeneratePackageScoreData generates individual data for each package.
// Value is the affected host count (matching Python behavior).
func (g *LLDGenerator) GeneratePackageScoreData(packages []PackageEntry) []zabbix.SenderData {
	var data []zabbix.SenderData

	for _, pkg := range packages {
		key := fmt.Sprintf("vulners.packages[%s,%s,%s]", pkg.Name, pkg.Version, pkg.Arch)
		data = append(data, zabbix.SenderData{
			Host:  g.naming.PackagesHost,
			Key:   key,
			Value: fmt.Sprintf("%d", len(pkg.AffectedHosts)),
		})
	}

	return data
}

// GenerateBulletinScoreData generates individual data for each bulletin.
// Value is the affected host count (matching Python behavior).
func (g *LLDGenerator) GenerateBulletinScoreData(bulletins []BulletinEntry) []zabbix.SenderData {
	var data []zabbix.SenderData

	for _, bulletin := range bulletins {
		data = append(data, zabbix.SenderData{
			Host:  g.naming.BulletinsHost,
			Key:   fmt.Sprintf("vulners.bulletins[%s]", bulletin.ID),
			Value: fmt.Sprintf("%d", len(bulletin.AffectedHosts)),
		})
	}

	return data
}

// GenerateStatisticsData generates statistics data using Python-compatible keys
// and backward-compatible Go keys.
func (g *LLDGenerator) GenerateStatisticsData(stats Statistics) []zabbix.SenderData {
	data := []zabbix.SenderData{
		// Python-compatible keys
		{Host: g.naming.StatisticsHost, Key: "vulners.TotalHosts", Value: fmt.Sprintf("%d", stats.TotalHosts)},
		{Host: g.naming.StatisticsHost, Key: "vulners.Maximum", Value: fmt.Sprintf("%.1f", stats.MaxCVSS)},
		{Host: g.naming.StatisticsHost, Key: "vulners.Average", Value: fmt.Sprintf("%.2f", stats.AvgCVSS)},
		{Host: g.naming.StatisticsHost, Key: "vulners.Minimum", Value: fmt.Sprintf("%.1f", stats.MinCVSS)},
		{Host: g.naming.StatisticsHost, Key: "vulners.scoreMedian", Value: fmt.Sprintf("%.1f", stats.MedianCVSS)},
		// Python scan.py aliases (vulners.score* keys)
		{Host: g.naming.StatisticsHost, Key: "vulners.scoreAverage", Value: fmt.Sprintf("%.2f", stats.AvgCVSS)},
		{Host: g.naming.StatisticsHost, Key: "vulners.scoreMaximum", Value: fmt.Sprintf("%.1f", stats.MaxCVSS)},
		{Host: g.naming.StatisticsHost, Key: "vulners.scoreMinimum", Value: fmt.Sprintf("%.1f", stats.MinCVSS)},
		// Go backward-compatible keys
		{Host: g.naming.StatisticsHost, Key: "vulners.stats[total_hosts]", Value: fmt.Sprintf("%d", stats.TotalHosts)},
		{Host: g.naming.StatisticsHost, Key: "vulners.stats[vuln_hosts]", Value: fmt.Sprintf("%d", stats.VulnerableHosts)},
		{Host: g.naming.StatisticsHost, Key: "vulners.stats[total_vulns]", Value: fmt.Sprintf("%d", stats.TotalPackages)},
		{Host: g.naming.StatisticsHost, Key: "vulners.stats[total_bulletins]", Value: fmt.Sprintf("%d", stats.TotalBulletins)},
		{Host: g.naming.StatisticsHost, Key: "vulners.stats[total_cves]", Value: fmt.Sprintf("%d", stats.TotalCVEs)},
		{Host: g.naming.StatisticsHost, Key: "vulners.stats[max_score]", Value: fmt.Sprintf("%.1f", stats.MaxCVSS)},
		{Host: g.naming.StatisticsHost, Key: "vulners.stats[avg_score]", Value: fmt.Sprintf("%.2f", stats.AvgCVSS)},
	}

	// Histogram buckets (Python-compatible)
	for i := 0; i <= 10; i++ {
		data = append(data, zabbix.SenderData{
			Host:  g.naming.StatisticsHost,
			Key:   fmt.Sprintf("vulners.hostsCountScore%d", i),
			Value: fmt.Sprintf("%d", stats.Histogram[i]),
		})
	}

	return data
}
