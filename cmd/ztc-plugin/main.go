package main

import (
	"fmt"
	"os"

	"golang.zabbix.com/sdk/plugin"
	"golang.zabbix.com/sdk/plugin/container"

	"github.com/kidoz/zabbix-threat-control-go/internal/agent2"
)

func main() {
	p := agent2.NewPlugin()

	err := plugin.RegisterMetrics(
		p, "VulnersThreatControl",
		"vulners.hosts_lld", "Returns LLD JSON for hosts.",
		"vulners.packages_lld", "Returns LLD JSON for packages.",
		"vulners.bulletins_lld", "Returns LLD JSON for bulletins.",
		"vulners.host.score", "Returns CVSS score for a host.",
		"vulners.package.score", "Returns CVSS score for a package.",
		"vulners.bulletin.score", "Returns CVSS score for a bulletin.",
		"vulners.stats", "Returns scan statistics.",
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to register metrics: %s\n", err)
		os.Exit(1)
	}

	h, err := container.NewHandler("VulnersThreatControl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create handler: %s\n", err)
		os.Exit(1)
	}

	if err := h.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "plugin execution failed: %s\n", err)
		os.Exit(1)
	}
}
