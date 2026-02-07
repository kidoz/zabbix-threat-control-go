package scanner

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
)

// testNaming returns default NamingConfig for tests.
func testNaming() config.NamingConfig {
	return config.DefaultConfig().Naming
}

func TestGenerateHostsLLD(t *testing.T) {
	gen := NewLLDGenerator(testNaming())

	t.Run("empty", func(t *testing.T) {
		data := gen.GenerateHostsLLD(nil)
		if len(data.Data) != 0 {
			t.Errorf("expected 0 entries, got %d", len(data.Data))
		}
	})

	t.Run("single host with all fields", func(t *testing.T) {
		hosts := []HostEntry{
			{
				HostID:        "100",
				Host:          "server1",
				Name:          "Web Server 1",
				Score:         7.5,
				OSName:        "ubuntu",
				OSVersion:     "20.04",
				CumulativeFix: "apt-get install openssl=1.1.1k",
			},
		}
		data := gen.GenerateHostsLLD(hosts)
		if len(data.Data) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(data.Data))
		}
		entry := data.Data[0]

		checks := map[string]interface{}{
			"{#H.ID}":    "100",
			"{#H.HOST}":  "server1",
			"{#H.VNAME}": "Web Server 1",
			"{#H.SCORE}": "7.5",
			"{#H.OS}":    "ubuntu",
			"{#H.OSVER}": "20.04",
			"{#H.FIX}":   "apt-get install openssl=1.1.1k",
		}
		for key, want := range checks {
			if entry[key] != want {
				t.Errorf("%s = %v, want %v", key, entry[key], want)
			}
		}
	})

	t.Run("empty cumulative fix", func(t *testing.T) {
		hosts := []HostEntry{{HostID: "1", CumulativeFix: ""}}
		data := gen.GenerateHostsLLD(hosts)
		if data.Data[0]["{#H.FIX}"] != "" {
			t.Errorf("{#H.FIX} should be empty, got %v", data.Data[0]["{#H.FIX}"])
		}
	})
}

func TestGeneratePackagesLLD(t *testing.T) {
	gen := NewLLDGenerator(testNaming())

	t.Run("empty", func(t *testing.T) {
		data := gen.GeneratePackagesLLD(nil)
		if len(data.Data) != 0 {
			t.Errorf("expected 0 entries, got %d", len(data.Data))
		}
	})

	t.Run("full package entry", func(t *testing.T) {
		pkgs := []PackageEntry{
			{
				Name:              "openssl",
				Version:           "1.1.1f",
				Arch:              "amd64",
				Score:             9.8,
				Fix:               "apt-get install openssl=1.1.1k",
				AffectedHosts:     []string{"10", "20", "30"},
				AffectedHostNames: []string{"web1", "web2", "db1"},
				Bulletins:         []string{"USN-5000-1", "USN-5001-1"},
			},
		}
		data := gen.GeneratePackagesLLD(pkgs)
		if len(data.Data) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(data.Data))
		}
		entry := data.Data[0]

		// Go-native macros
		if entry["{#P.NAME}"] != "openssl" {
			t.Errorf("{#P.NAME} = %v, want openssl", entry["{#P.NAME}"])
		}
		if entry["{#P.VERSION}"] != "1.1.1f" {
			t.Errorf("{#P.VERSION} = %v, want 1.1.1f", entry["{#P.VERSION}"])
		}
		if entry["{#P.ARCH}"] != "amd64" {
			t.Errorf("{#P.ARCH} = %v, want amd64", entry["{#P.ARCH}"])
		}
		if entry["{#P.AFFECTED}"] != 3 {
			t.Errorf("{#P.AFFECTED} = %v, want 3", entry["{#P.AFFECTED}"])
		}
		if entry["{#P.HOSTS}"] != "10,20,30" {
			t.Errorf("{#P.HOSTS} = %v, want 10,20,30", entry["{#P.HOSTS}"])
		}

		// Python-compatible macros
		if entry["{#PKG.ID}"] != "openssl 1.1.1f amd64" {
			t.Errorf("{#PKG.ID} = %v, want 'openssl 1.1.1f amd64'", entry["{#PKG.ID}"])
		}
		if entry["{#PKG.SCORE}"] != "9.8" {
			t.Errorf("{#PKG.SCORE} = %v, want 9.8", entry["{#PKG.SCORE}"])
		}
		// impact = 3 hosts * 9.8 score = 29
		if entry["{#PKG.IMPACT}"] != 29 {
			t.Errorf("{#PKG.IMPACT} = %v, want 29", entry["{#PKG.IMPACT}"])
		}
		if entry["{#PKG.URL}"] != "USN-5000-1" {
			t.Errorf("{#PKG.URL} = %v, want USN-5000-1", entry["{#PKG.URL}"])
		}
		if entry["{#PKG.HOSTS}"] != "web1\nweb2\ndb1" {
			t.Errorf("{#PKG.HOSTS} = %v, want newline-separated host names", entry["{#PKG.HOSTS}"])
		}
		if entry["{#PKG.FIX}"] != "apt-get install openssl=1.1.1k" {
			t.Errorf("{#PKG.FIX} = %v", entry["{#PKG.FIX}"])
		}
	})

	t.Run("no bulletins gives empty URL", func(t *testing.T) {
		pkgs := []PackageEntry{{Name: "curl", Bulletins: nil}}
		data := gen.GeneratePackagesLLD(pkgs)
		if data.Data[0]["{#PKG.URL}"] != "" {
			t.Errorf("{#PKG.URL} should be empty when no bulletins, got %v", data.Data[0]["{#PKG.URL}"])
		}
	})

	t.Run("impact calculation with zero hosts", func(t *testing.T) {
		pkgs := []PackageEntry{{Name: "curl", Score: 5.0, AffectedHosts: nil}}
		data := gen.GeneratePackagesLLD(pkgs)
		if data.Data[0]["{#PKG.IMPACT}"] != 0 {
			t.Errorf("{#PKG.IMPACT} = %v, want 0 for no affected hosts", data.Data[0]["{#PKG.IMPACT}"])
		}
	})
}

func TestGenerateBulletinsLLD(t *testing.T) {
	gen := NewLLDGenerator(testNaming())

	t.Run("empty", func(t *testing.T) {
		data := gen.GenerateBulletinsLLD(nil)
		if len(data.Data) != 0 {
			t.Errorf("expected 0 entries, got %d", len(data.Data))
		}
	})

	t.Run("full bulletin entry", func(t *testing.T) {
		bulletins := []BulletinEntry{
			{
				ID:                "USN-5000-1",
				Type:              "ubuntu",
				Score:             8.0,
				CVEs:              []string{"CVE-2021-1234", "CVE-2021-5678"},
				AffectedPkgs:      []string{"openssl 1.1.1f amd64"},
				AffectedHosts:     []string{"10", "20"},
				AffectedHostNames: []string{"web1", "db1"},
			},
		}
		data := gen.GenerateBulletinsLLD(bulletins)
		if len(data.Data) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(data.Data))
		}
		entry := data.Data[0]

		// Go-native macros
		if entry["{#B.ID}"] != "USN-5000-1" {
			t.Errorf("{#B.ID} = %v", entry["{#B.ID}"])
		}
		if entry["{#B.TYPE}"] != "ubuntu" {
			t.Errorf("{#B.TYPE} = %v", entry["{#B.TYPE}"])
		}
		if entry["{#B.SCORE}"] != "8.0" {
			t.Errorf("{#B.SCORE} = %v", entry["{#B.SCORE}"])
		}
		if entry["{#B.CVES}"] != "CVE-2021-1234,CVE-2021-5678" {
			t.Errorf("{#B.CVES} = %v", entry["{#B.CVES}"])
		}
		if entry["{#B.AFFECTED}"] != 2 {
			t.Errorf("{#B.AFFECTED} = %v, want 2", entry["{#B.AFFECTED}"])
		}
		if entry["{#B.HOSTS}"] != "10,20" {
			t.Errorf("{#B.HOSTS} = %v, want '10,20'", entry["{#B.HOSTS}"])
		}

		// Python-compatible macros
		if entry["{#BULLETIN.ID}"] != "USN-5000-1" {
			t.Errorf("{#BULLETIN.ID} = %v", entry["{#BULLETIN.ID}"])
		}
		if entry["{#BULLETIN.SCORE}"] != "8.0" {
			t.Errorf("{#BULLETIN.SCORE} = %v", entry["{#BULLETIN.SCORE}"])
		}
		// impact = 2 hosts * 8.0 = 16
		if entry["{#BULLETIN.IMPACT}"] != 16 {
			t.Errorf("{#BULLETIN.IMPACT} = %v, want 16", entry["{#BULLETIN.IMPACT}"])
		}
		if entry["{#BULLETIN.HOSTS}"] != "web1\ndb1" {
			t.Errorf("{#BULLETIN.HOSTS} = %v, want 'web1\\ndb1'", entry["{#BULLETIN.HOSTS}"])
		}
	})

	t.Run("impact with fractional score", func(t *testing.T) {
		bulletins := []BulletinEntry{
			{
				ID:            "B1",
				Score:         7.5,
				AffectedHosts: []string{"1", "2", "3"},
			},
		}
		data := gen.GenerateBulletinsLLD(bulletins)
		// impact = int(3 * 7.5) = int(22.5) = 22
		if data.Data[0]["{#BULLETIN.IMPACT}"] != 22 {
			t.Errorf("{#BULLETIN.IMPACT} = %v, want 22", data.Data[0]["{#BULLETIN.IMPACT}"])
		}
	})
}

func TestGenerateHostScoreData(t *testing.T) {
	naming := testNaming()
	gen := NewLLDGenerator(naming)

	t.Run("empty", func(t *testing.T) {
		data := gen.GenerateHostScoreData(nil)
		if len(data) != 0 {
			t.Errorf("expected 0 items, got %d", len(data))
		}
	})

	t.Run("host score is CVSS score", func(t *testing.T) {
		hosts := []HostEntry{
			{HostID: "42", Score: 7.5},
			{HostID: "43", Score: 0.0},
		}
		data := gen.GenerateHostScoreData(hosts)
		if len(data) != 2 {
			t.Fatalf("expected 2 items, got %d", len(data))
		}
		if data[0].Host != naming.HostsHost {
			t.Errorf("Host = %q, want %q", data[0].Host, naming.HostsHost)
		}
		if data[0].Key != "vulners.hosts[42]" {
			t.Errorf("Key = %q, want vulners.hosts[42]", data[0].Key)
		}
		if data[0].Value != "7.5" {
			t.Errorf("Value = %q, want 7.5", data[0].Value)
		}
		if data[1].Value != "0.0" {
			t.Errorf("Value = %q, want 0.0", data[1].Value)
		}
	})
}

func TestGeneratePackageScoreData_HostCount(t *testing.T) {
	naming := testNaming()
	gen := NewLLDGenerator(naming)

	t.Run("value is affected host count not CVSS", func(t *testing.T) {
		pkgs := []PackageEntry{
			{
				Name:          "openssl",
				Version:       "1.1.1f",
				Arch:          "amd64",
				Score:         9.8,
				AffectedHosts: []string{"10", "20", "30"},
			},
		}
		data := gen.GeneratePackageScoreData(pkgs)
		if len(data) != 1 {
			t.Fatalf("expected 1 item, got %d", len(data))
		}
		if data[0].Host != naming.PackagesHost {
			t.Errorf("Host = %q", data[0].Host)
		}
		if data[0].Key != "vulners.packages[openssl,1.1.1f,amd64]" {
			t.Errorf("Key = %q", data[0].Key)
		}
		// Must be host count (3), not CVSS (9.8)
		if data[0].Value != "3" {
			t.Errorf("Value = %q, want '3' (host count), not CVSS score", data[0].Value)
		}
	})

	t.Run("empty affected hosts gives zero", func(t *testing.T) {
		pkgs := []PackageEntry{
			{Name: "curl", Version: "7.68", Arch: "amd64", Score: 5.0},
		}
		data := gen.GeneratePackageScoreData(pkgs)
		if data[0].Value != "0" {
			t.Errorf("Value = %q, want '0'", data[0].Value)
		}
	})
}

func TestGenerateBulletinScoreData_HostCount(t *testing.T) {
	naming := testNaming()
	gen := NewLLDGenerator(naming)

	t.Run("value is affected host count not CVSS", func(t *testing.T) {
		bulletins := []BulletinEntry{
			{
				ID:            "USN-5000-1",
				Score:         8.5,
				AffectedHosts: []string{"10", "20"},
			},
		}
		data := gen.GenerateBulletinScoreData(bulletins)
		if len(data) != 1 {
			t.Fatalf("expected 1 item, got %d", len(data))
		}
		if data[0].Host != naming.BulletinsHost {
			t.Errorf("Host = %q", data[0].Host)
		}
		if data[0].Key != "vulners.bulletins[USN-5000-1]" {
			t.Errorf("Key = %q", data[0].Key)
		}
		// Must be host count (2), not CVSS (8.5)
		if data[0].Value != "2" {
			t.Errorf("Value = %q, want '2' (host count), not CVSS score", data[0].Value)
		}
	})
}

func TestGenerateStatisticsData(t *testing.T) {
	naming := testNaming()
	gen := NewLLDGenerator(naming)

	stats := Statistics{
		TotalHosts:      10,
		VulnerableHosts: 7,
		TotalPackages:   25,
		TotalBulletins:  15,
		TotalCVEs:       42,
		MaxCVSS:         9.8,
		AvgCVSS:         6.25,
		MinCVSS:         2.1,
		MedianCVSS:      5.5,
		Histogram:       [11]int{3, 0, 1, 0, 2, 1, 0, 1, 0, 1, 1},
	}

	data := gen.GenerateStatisticsData(stats)

	// Build key→value map for easy lookup
	kvMap := make(map[string]string)
	for _, d := range data {
		kvMap[d.Key] = d.Value
		if d.Host != naming.StatisticsHost {
			t.Errorf("item %q has wrong host: %q", d.Key, d.Host)
		}
	}

	t.Run("python-compatible keys present", func(t *testing.T) {
		pythonKeys := []struct {
			key  string
			want string
		}{
			{"vulners.TotalHosts", "10"},
			{"vulners.Maximum", "9.8"},
			{"vulners.Average", "6.25"},
			{"vulners.Minimum", "2.1"},
			{"vulners.scoreMedian", "5.5"},
		}
		for _, tc := range pythonKeys {
			if got, ok := kvMap[tc.key]; !ok {
				t.Errorf("missing Python-compatible key %q", tc.key)
			} else if got != tc.want {
				t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
			}
		}
	})

	t.Run("go backward-compatible keys present", func(t *testing.T) {
		goKeys := []struct {
			key  string
			want string
		}{
			{"vulners.stats[total_hosts]", "10"},
			{"vulners.stats[vuln_hosts]", "7"},
			{"vulners.stats[total_vulns]", "25"},
			{"vulners.stats[total_bulletins]", "15"},
			{"vulners.stats[total_cves]", "42"},
			{"vulners.stats[max_score]", "9.8"},
			{"vulners.stats[avg_score]", "6.25"},
		}
		for _, tc := range goKeys {
			if got, ok := kvMap[tc.key]; !ok {
				t.Errorf("missing Go backward-compat key %q", tc.key)
			} else if got != tc.want {
				t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
			}
		}
	})

	t.Run("histogram buckets", func(t *testing.T) {
		for i := 0; i <= 10; i++ {
			key := fmt.Sprintf("vulners.hostsCountScore%d", i)
			want := fmt.Sprintf("%d", stats.Histogram[i])
			if got, ok := kvMap[key]; !ok {
				t.Errorf("missing histogram key %q", key)
			} else if got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
	})

	t.Run("python scan.py score alias keys present", func(t *testing.T) {
		scoreAliases := []struct {
			key  string
			want string
		}{
			{"vulners.scoreAverage", "6.25"},
			{"vulners.scoreMaximum", "9.8"},
			{"vulners.scoreMinimum", "2.1"},
		}
		for _, tc := range scoreAliases {
			if got, ok := kvMap[tc.key]; !ok {
				t.Errorf("missing Python scan.py alias key %q", tc.key)
			} else if got != tc.want {
				t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
			}
		}
	})

	t.Run("total item count", func(t *testing.T) {
		// 5 Python prepare + 3 Python scan aliases + 7 Go-compat + 11 histogram = 26
		if len(data) != 26 {
			t.Errorf("expected 26 data items, got %d", len(data))
		}
	})
}

func TestGenerateStatisticsData_ZeroStats(t *testing.T) {
	gen := NewLLDGenerator(testNaming())
	data := gen.GenerateStatisticsData(Statistics{})

	kvMap := make(map[string]string)
	for _, d := range data {
		kvMap[d.Key] = d.Value
	}

	if kvMap["vulners.TotalHosts"] != "0" {
		t.Errorf("TotalHosts = %q, want '0'", kvMap["vulners.TotalHosts"])
	}
	if kvMap["vulners.scoreMedian"] != "0.0" {
		t.Errorf("scoreMedian = %q, want '0.0'", kvMap["vulners.scoreMedian"])
	}
	for i := 0; i <= 10; i++ {
		key := fmt.Sprintf("vulners.hostsCountScore%d", i)
		if kvMap[key] != "0" {
			t.Errorf("%s = %q, want '0'", key, kvMap[key])
		}
	}
}

func TestGenerateMultiplePackagesLLD(t *testing.T) {
	gen := NewLLDGenerator(testNaming())

	pkgs := []PackageEntry{
		{Name: "openssl", Version: "1.1.1f", Arch: "amd64", Score: 9.8, AffectedHosts: []string{"1", "2"}},
		{Name: "curl", Version: "7.68", Arch: "i386", Score: 5.0, AffectedHosts: []string{"1"}},
	}

	data := gen.GeneratePackagesLLD(pkgs)
	if len(data.Data) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(data.Data))
	}

	// Verify keys exist for both entries
	for i, entry := range data.Data {
		requiredKeys := []string{"{#P.NAME}", "{#P.VERSION}", "{#P.ARCH}", "{#P.SCORE}",
			"{#PKG.ID}", "{#PKG.SCORE}", "{#PKG.IMPACT}", "{#PKG.URL}", "{#PKG.HOSTS}", "{#PKG.FIX}"}
		for _, key := range requiredKeys {
			if _, ok := entry[key]; !ok {
				t.Errorf("entry %d missing key %s", i, key)
			}
		}
	}
}

func TestLLDHostNamesNewlineSeparated(t *testing.T) {
	gen := NewLLDGenerator(testNaming())

	t.Run("package hosts use newlines", func(t *testing.T) {
		pkgs := []PackageEntry{
			{
				Name:              "curl",
				AffectedHostNames: []string{"Server A", "Server B", "Server C"},
			},
		}
		data := gen.GeneratePackagesLLD(pkgs)
		hosts := data.Data[0]["{#PKG.HOSTS}"].(string)
		if strings.Count(hosts, "\n") != 2 {
			t.Errorf("expected 2 newlines, got %d in %q", strings.Count(hosts, "\n"), hosts)
		}
		if hosts != "Server A\nServer B\nServer C" {
			t.Errorf("{#PKG.HOSTS} = %q", hosts)
		}
	})

	t.Run("bulletin hosts use newlines", func(t *testing.T) {
		bulletins := []BulletinEntry{
			{
				ID:                "B1",
				AffectedHostNames: []string{"Alpha", "Beta"},
			},
		}
		data := gen.GenerateBulletinsLLD(bulletins)
		hosts := data.Data[0]["{#BULLETIN.HOSTS}"].(string)
		if hosts != "Alpha\nBeta" {
			t.Errorf("{#BULLETIN.HOSTS} = %q", hosts)
		}
	})

	t.Run("single host no newline", func(t *testing.T) {
		pkgs := []PackageEntry{
			{Name: "curl", AffectedHostNames: []string{"OnlyHost"}},
		}
		data := gen.GeneratePackagesLLD(pkgs)
		hosts := data.Data[0]["{#PKG.HOSTS}"].(string)
		if strings.Contains(hosts, "\n") {
			t.Errorf("single host should have no newline: %q", hosts)
		}
	})

	t.Run("no hosts gives empty string", func(t *testing.T) {
		pkgs := []PackageEntry{{Name: "curl"}}
		data := gen.GeneratePackagesLLD(pkgs)
		if data.Data[0]["{#PKG.HOSTS}"] != "" {
			t.Errorf("expected empty, got %q", data.Data[0]["{#PKG.HOSTS}"])
		}
	})
}
