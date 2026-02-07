package scanner

import (
	"math"
	"testing"
)

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name    string
		slice   []string
		value   string
		wantLen int
	}{
		{"nil slice", nil, "a", 1},
		{"new value", []string{"a"}, "b", 2},
		{"duplicate", []string{"a", "b"}, "a", 2},
		{"empty string", []string{}, "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendUnique(tt.slice, tt.value)
			if len(got) != tt.wantLen {
				t.Errorf("appendUnique() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestAppendUniqueSlice(t *testing.T) {
	tests := []struct {
		name    string
		dst     []string
		src     []string
		wantLen int
	}{
		{"empty dst and src", nil, nil, 0},
		{"empty dst", nil, []string{"a", "b"}, 2},
		{"empty src", []string{"a"}, nil, 1},
		{"overlaps", []string{"a", "b"}, []string{"b", "c"}, 3},
		{"disjoint", []string{"a"}, []string{"b", "c"}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendUniqueSlice(tt.dst, tt.src)
			if len(got) != tt.wantLen {
				t.Errorf("appendUniqueSlice() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestFilterByMinCVSS(t *testing.T) {
	pkgs := []PackageVuln{
		{Name: "a", Score: 3.0},
		{Name: "b", Score: 7.5},
		{Name: "c", Score: 5.0},
		{Name: "d", Score: 9.8},
	}

	tests := []struct {
		name     string
		packages []PackageVuln
		minScore float64
		wantLen  int
	}{
		{"empty", nil, 5.0, 0},
		{"all above", pkgs, 1.0, 4},
		{"all below", pkgs, 10.0, 0},
		{"boundary >=", pkgs, 5.0, 3}, // b=7.5, c=5.0, d=9.8
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterByMinCVSS(tt.packages, tt.minScore)
			if len(got) != tt.wantLen {
				t.Errorf("FilterByMinCVSS() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestAggregator_AddHost_GetResults(t *testing.T) {
	t.Run("zero hosts", func(t *testing.T) {
		agg := NewAggregator()
		results := agg.GetResults()
		if results.HostsScanned != 0 {
			t.Errorf("HostsScanned = %d, want 0", results.HostsScanned)
		}
	})

	t.Run("one host with vulns", func(t *testing.T) {
		agg := NewAggregator()
		agg.AddHost(HostEntry{
			HostID: "1",
			Score:  7.5,
			Packages: []PackageVuln{
				{Name: "nginx", Version: "1.18", Score: 7.5, Bulletins: []string{"CVE-2021-1234"}},
			},
			Bulletins: []BulletinSummary{
				{ID: "CVE-2021-1234", Score: 7.5, CVEs: []string{"CVE-2021-1234"}},
			},
		})
		results := agg.GetResults()
		if results.HostsScanned != 1 {
			t.Errorf("HostsScanned = %d, want 1", results.HostsScanned)
		}
		if results.HostsWithVulns != 1 {
			t.Errorf("HostsWithVulns = %d, want 1", results.HostsWithVulns)
		}
		if results.MaxCVSS != 7.5 {
			t.Errorf("MaxCVSS = %f, want 7.5", results.MaxCVSS)
		}
	})

	t.Run("overlapping packages score-takes-max and dedup hosts", func(t *testing.T) {
		agg := NewAggregator()
		agg.AddHost(HostEntry{
			HostID: "1",
			Score:  5.0,
			Packages: []PackageVuln{
				{Name: "openssl", Version: "1.1.1", Score: 5.0},
			},
		})
		agg.AddHost(HostEntry{
			HostID: "2",
			Score:  9.0,
			Packages: []PackageVuln{
				{Name: "openssl", Version: "1.1.1", Score: 9.0},
			},
		})
		// Add host 1 again (should dedup)
		agg.AddHost(HostEntry{
			HostID: "1",
			Score:  5.0,
			Packages: []PackageVuln{
				{Name: "openssl", Version: "1.1.1", Score: 5.0},
			},
		})
		results := agg.GetResults()
		if len(results.Packages) != 1 {
			t.Fatalf("expected 1 package, got %d", len(results.Packages))
		}
		if results.Packages[0].Score != 9.0 {
			t.Errorf("package score = %f, want 9.0 (max)", results.Packages[0].Score)
		}
		if len(results.Packages[0].AffectedHosts) != 2 {
			t.Errorf("affected hosts = %d, want 2 (deduped)", len(results.Packages[0].AffectedHosts))
		}
	})

	t.Run("sort descending", func(t *testing.T) {
		agg := NewAggregator()
		agg.AddHost(HostEntry{
			HostID: "1",
			Score:  3.0,
			Packages: []PackageVuln{
				{Name: "a", Version: "1", Score: 3.0},
				{Name: "b", Version: "1", Score: 9.0},
				{Name: "c", Version: "1", Score: 6.0},
			},
		})
		results := agg.GetResults()
		if len(results.Packages) < 2 {
			t.Fatal("expected at least 2 packages")
		}
		for i := 1; i < len(results.Packages); i++ {
			if results.Packages[i].Score > results.Packages[i-1].Score {
				t.Errorf("packages not sorted descending: %f > %f at index %d",
					results.Packages[i].Score, results.Packages[i-1].Score, i)
			}
		}
	})
}

func TestAggregator_GetStatistics(t *testing.T) {
	agg := NewAggregator()
	agg.AddHost(HostEntry{
		HostID: "1",
		Score:  7.5,
		Packages: []PackageVuln{
			{Name: "nginx", Version: "1.18", Score: 7.5},
		},
		Bulletins: []BulletinSummary{
			{ID: "B1", Score: 7.5, CVEs: []string{"CVE-2021-1234", "CVE-2021-5678"}},
		},
	})
	agg.AddHost(HostEntry{
		HostID: "2",
		Score:  5.0,
		Packages: []PackageVuln{
			{Name: "openssl", Version: "1.1", Score: 5.0},
		},
		Bulletins: []BulletinSummary{
			{ID: "B2", Score: 5.0, CVEs: []string{"CVE-2021-5678", "CVE-2021-9999"}},
		},
	})
	agg.AddHost(HostEntry{
		HostID: "3",
		Score:  0, // not vulnerable
	})

	stats := agg.GetStatistics()

	if stats.TotalHosts != 3 {
		t.Errorf("TotalHosts = %d, want 3", stats.TotalHosts)
	}
	if stats.VulnerableHosts != 2 {
		t.Errorf("VulnerableHosts = %d, want 2", stats.VulnerableHosts)
	}
	if stats.MaxCVSS != 7.5 {
		t.Errorf("MaxCVSS = %f, want 7.5", stats.MaxCVSS)
	}
	// Average is over ALL hosts (including score=0), matching Python
	expectedAvg := (7.5 + 5.0 + 0) / 3.0
	if math.Abs(stats.AvgCVSS-expectedAvg) > 0.001 {
		t.Errorf("AvgCVSS = %f, want %f", stats.AvgCVSS, expectedAvg)
	}
	// CVEs: CVE-2021-1234, CVE-2021-5678, CVE-2021-9999 = 3 unique
	if stats.TotalCVEs != 3 {
		t.Errorf("TotalCVEs = %d, want 3", stats.TotalCVEs)
	}
}

func TestAggregator_AffectedHostNames(t *testing.T) {
	t.Run("package host names tracked", func(t *testing.T) {
		agg := NewAggregator()
		agg.AddHost(HostEntry{
			HostID: "1",
			Name:   "Web Server 1",
			Score:  5.0,
			Packages: []PackageVuln{
				{Name: "openssl", Version: "1.1.1", Score: 5.0},
			},
		})
		agg.AddHost(HostEntry{
			HostID: "2",
			Name:   "DB Server",
			Score:  7.0,
			Packages: []PackageVuln{
				{Name: "openssl", Version: "1.1.1", Score: 7.0},
			},
		})

		results := agg.GetResults()
		if len(results.Packages) != 1 {
			t.Fatalf("expected 1 package, got %d", len(results.Packages))
		}
		names := results.Packages[0].AffectedHostNames
		if len(names) != 2 {
			t.Fatalf("expected 2 host names, got %d", len(names))
		}
		if names[0] != "Web Server 1" || names[1] != "DB Server" {
			t.Errorf("AffectedHostNames = %v", names)
		}
	})

	t.Run("bulletin host names tracked", func(t *testing.T) {
		agg := NewAggregator()
		agg.AddHost(HostEntry{
			HostID: "1",
			Name:   "Alpha",
			Score:  5.0,
			Bulletins: []BulletinSummary{
				{ID: "B1", Score: 5.0, CVEs: []string{"CVE-1"}},
			},
		})
		agg.AddHost(HostEntry{
			HostID: "2",
			Name:   "Beta",
			Score:  6.0,
			Bulletins: []BulletinSummary{
				{ID: "B1", Score: 6.0, CVEs: []string{"CVE-1"}},
			},
		})

		results := agg.GetResults()
		if len(results.Bulletins) != 1 {
			t.Fatalf("expected 1 bulletin, got %d", len(results.Bulletins))
		}
		names := results.Bulletins[0].AffectedHostNames
		if len(names) != 2 {
			t.Fatalf("expected 2 host names, got %d", len(names))
		}
		if names[0] != "Alpha" || names[1] != "Beta" {
			t.Errorf("AffectedHostNames = %v", names)
		}
	})

	t.Run("duplicate host names deduped", func(t *testing.T) {
		agg := NewAggregator()
		agg.AddHost(HostEntry{
			HostID: "1",
			Name:   "Same Name",
			Score:  5.0,
			Packages: []PackageVuln{
				{Name: "curl", Version: "7.68", Score: 5.0},
			},
		})
		// Same host again
		agg.AddHost(HostEntry{
			HostID: "1",
			Name:   "Same Name",
			Score:  5.0,
			Packages: []PackageVuln{
				{Name: "curl", Version: "7.68", Score: 5.0},
			},
		})

		results := agg.GetResults()
		if len(results.Packages[0].AffectedHostNames) != 1 {
			t.Errorf("expected 1 deduped host name, got %d", len(results.Packages[0].AffectedHostNames))
		}
	})
}

func TestAggregator_GetStatistics_Extended(t *testing.T) {
	t.Run("median odd count", func(t *testing.T) {
		agg := NewAggregator()
		// 3 vulnerable hosts: scores 3.0, 5.0, 9.0 → median = 5.0
		agg.AddHost(HostEntry{HostID: "1", Score: 9.0})
		agg.AddHost(HostEntry{HostID: "2", Score: 3.0})
		agg.AddHost(HostEntry{HostID: "3", Score: 5.0})

		stats := agg.GetStatistics()
		if stats.MedianCVSS != 5.0 {
			t.Errorf("MedianCVSS = %f, want 5.0", stats.MedianCVSS)
		}
		if stats.MinCVSS != 3.0 {
			t.Errorf("MinCVSS = %f, want 3.0", stats.MinCVSS)
		}
	})

	t.Run("median even count", func(t *testing.T) {
		agg := NewAggregator()
		// 4 vulnerable hosts: scores 2.0, 4.0, 6.0, 8.0 → median = (4.0+6.0)/2 = 5.0
		agg.AddHost(HostEntry{HostID: "1", Score: 8.0})
		agg.AddHost(HostEntry{HostID: "2", Score: 2.0})
		agg.AddHost(HostEntry{HostID: "3", Score: 6.0})
		agg.AddHost(HostEntry{HostID: "4", Score: 4.0})

		stats := agg.GetStatistics()
		if stats.MedianCVSS != 5.0 {
			t.Errorf("MedianCVSS = %f, want 5.0", stats.MedianCVSS)
		}
	})

	t.Run("single vulnerable host", func(t *testing.T) {
		agg := NewAggregator()
		agg.AddHost(HostEntry{HostID: "1", Score: 7.5})

		stats := agg.GetStatistics()
		if stats.MedianCVSS != 7.5 {
			t.Errorf("MedianCVSS = %f, want 7.5", stats.MedianCVSS)
		}
		if stats.MinCVSS != 7.5 {
			t.Errorf("MinCVSS = %f, want 7.5", stats.MinCVSS)
		}
	})

	t.Run("no vulnerable hosts gives zero", func(t *testing.T) {
		agg := NewAggregator()
		agg.AddHost(HostEntry{HostID: "1", Score: 0})
		agg.AddHost(HostEntry{HostID: "2", Score: 0})

		stats := agg.GetStatistics()
		if stats.MedianCVSS != 0 {
			t.Errorf("MedianCVSS = %f, want 0", stats.MedianCVSS)
		}
		if stats.MinCVSS != 0 {
			t.Errorf("MinCVSS = %f, want 0", stats.MinCVSS)
		}
	})

	t.Run("histogram buckets", func(t *testing.T) {
		agg := NewAggregator()
		agg.AddHost(HostEntry{HostID: "1", Score: 0})    // bucket 0
		agg.AddHost(HostEntry{HostID: "2", Score: 0})    // bucket 0
		agg.AddHost(HostEntry{HostID: "3", Score: 3.5})  // bucket 3
		agg.AddHost(HostEntry{HostID: "4", Score: 7.9})  // bucket 7
		agg.AddHost(HostEntry{HostID: "5", Score: 10.0}) // bucket 10

		stats := agg.GetStatistics()
		if stats.Histogram[0] != 2 {
			t.Errorf("Histogram[0] = %d, want 2", stats.Histogram[0])
		}
		if stats.Histogram[3] != 1 {
			t.Errorf("Histogram[3] = %d, want 1", stats.Histogram[3])
		}
		if stats.Histogram[7] != 1 {
			t.Errorf("Histogram[7] = %d, want 1", stats.Histogram[7])
		}
		if stats.Histogram[10] != 1 {
			t.Errorf("Histogram[10] = %d, want 1", stats.Histogram[10])
		}
		// All other buckets should be 0
		for i, count := range stats.Histogram {
			if i != 0 && i != 3 && i != 7 && i != 10 && count != 0 {
				t.Errorf("Histogram[%d] = %d, want 0", i, count)
			}
		}
	})

	t.Run("histogram includes non-vulnerable hosts in bucket 0", func(t *testing.T) {
		agg := NewAggregator()
		agg.AddHost(HostEntry{HostID: "1", Score: 0})
		agg.AddHost(HostEntry{HostID: "2", Score: 5.0})

		stats := agg.GetStatistics()
		if stats.Histogram[0] != 1 {
			t.Errorf("Histogram[0] = %d, want 1 (non-vulnerable host)", stats.Histogram[0])
		}
		if stats.Histogram[5] != 1 {
			t.Errorf("Histogram[5] = %d, want 1", stats.Histogram[5])
		}
	})

	t.Run("min and median include zero-score hosts (Python parity)", func(t *testing.T) {
		agg := NewAggregator()
		agg.AddHost(HostEntry{HostID: "1", Score: 0}) // non-vulnerable
		agg.AddHost(HostEntry{HostID: "2", Score: 3.0})
		agg.AddHost(HostEntry{HostID: "3", Score: 9.0})

		stats := agg.GetStatistics()
		// All 3 hosts (0, 3.0, 9.0) → sorted: [0, 3.0, 9.0] → median = 3.0
		if stats.MedianCVSS != 3.0 {
			t.Errorf("MedianCVSS = %f, want 3.0", stats.MedianCVSS)
		}
		// Min includes 0-score hosts
		if stats.MinCVSS != 0 {
			t.Errorf("MinCVSS = %f, want 0", stats.MinCVSS)
		}
	})

	t.Run("empty aggregator", func(t *testing.T) {
		agg := NewAggregator()
		stats := agg.GetStatistics()
		if stats.MedianCVSS != 0 {
			t.Errorf("MedianCVSS = %f, want 0", stats.MedianCVSS)
		}
		if stats.MinCVSS != 0 {
			t.Errorf("MinCVSS = %f, want 0", stats.MinCVSS)
		}
		for i, count := range stats.Histogram {
			if count != 0 {
				t.Errorf("Histogram[%d] = %d, want 0", i, count)
			}
		}
	})
}

func TestAggregator_Reset(t *testing.T) {
	agg := NewAggregator()
	agg.AddHost(HostEntry{
		HostID: "1",
		Score:  7.5,
		Packages: []PackageVuln{
			{Name: "nginx", Version: "1.18", Score: 7.5},
		},
	})

	agg.Reset()

	stats := agg.GetStatistics()
	if stats.TotalHosts != 0 {
		t.Errorf("after Reset, TotalHosts = %d, want 0", stats.TotalHosts)
	}
	if stats.TotalPackages != 0 {
		t.Errorf("after Reset, TotalPackages = %d, want 0", stats.TotalPackages)
	}
}
