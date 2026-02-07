package scanner

import (
	vulners "github.com/kidoz/go-vulners"
)

// extractVulnPackages converts a library AuditResult into scanner PackageVuln entries.
func extractVulnPackages(result *vulners.AuditResult) []PackageVuln {
	if result == nil || len(result.Vulnerabilities) == 0 {
		return nil
	}

	// Group vulnerabilities by package name to aggregate bulletins/CVEs per package
	type pkgAgg struct {
		name      string
		version   string
		arch      string
		maxScore  float64
		fix       string
		bulletins []string
		cves      []string
	}

	pkgMap := make(map[string]*pkgAgg)

	for _, v := range result.Vulnerabilities {
		name, version, arch := ParsePackageString(v.Package)
		key := v.Package

		agg, exists := pkgMap[key]
		if !exists {
			agg = &pkgAgg{
				name:    name,
				version: version,
				arch:    arch,
				fix:     v.Fix,
			}
			pkgMap[key] = agg
		}

		var score float64
		if v.CVSS != nil {
			score = v.CVSS.Score
		}
		if score > agg.maxScore {
			agg.maxScore = score
		}

		if v.BulletinID != "" {
			agg.bulletins = append(agg.bulletins, v.BulletinID)
		}
		agg.cves = append(agg.cves, v.CVEList...)
	}

	var vulns []PackageVuln
	for _, agg := range pkgMap {
		vulns = append(vulns, PackageVuln{
			Name:      agg.name,
			Version:   agg.version,
			Arch:      agg.arch,
			Score:     agg.maxScore,
			Fix:       agg.fix,
			Bulletins: agg.bulletins,
			CVEs:      agg.cves,
		})
	}

	return vulns
}

// extractBulletins converts a library AuditResult into scanner BulletinSummary entries.
func extractBulletins(result *vulners.AuditResult) []BulletinSummary {
	if result == nil || len(result.Vulnerabilities) == 0 {
		return nil
	}

	type bulletinAgg struct {
		id          string
		maxScore    float64
		cves        []string
		fix         string
		affectedPkg []string
	}

	bMap := make(map[string]*bulletinAgg)

	for _, v := range result.Vulnerabilities {
		if v.BulletinID == "" {
			continue
		}
		agg, exists := bMap[v.BulletinID]
		if !exists {
			var score float64
			if v.CVSS != nil {
				score = v.CVSS.Score
			}
			agg = &bulletinAgg{
				id:       v.BulletinID,
				maxScore: score,
				cves:     v.CVEList,
				fix:      v.Fix,
			}
			bMap[v.BulletinID] = agg
		} else {
			if v.CVSS != nil && v.CVSS.Score > agg.maxScore {
				agg.maxScore = v.CVSS.Score
			}
			agg.cves = appendUniqueCVEs(agg.cves, v.CVEList)
		}
		agg.affectedPkg = append(agg.affectedPkg, v.Package)
	}

	var bulletins []BulletinSummary
	for _, agg := range bMap {
		bulletins = append(bulletins, BulletinSummary{
			ID:          agg.id,
			Score:       agg.maxScore,
			CVEs:        agg.cves,
			Fix:         agg.fix,
			AffectedPkg: agg.affectedPkg,
		})
	}

	return bulletins
}

// appendUniqueCVEs merges CVEs from src into dst, skipping duplicates.
func appendUniqueCVEs(dst, src []string) []string {
	existing := make(map[string]bool, len(dst))
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
