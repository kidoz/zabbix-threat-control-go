package zabbix

import (
	"context"
	"fmt"

	"log/slog"
)

// EnsureVirtualHosts creates virtual hosts for aggregated vulnerability data
func (c *Client) EnsureVirtualHosts() error {
	return c.EnsureVirtualHostsCtx(context.Background(), false)
}

// EnsureVirtualHostsCtx creates virtual hosts with context.
// When force is true, existing templates and hosts are updated/recreated.
func (c *Client) EnsureVirtualHostsCtx(ctx context.Context, force bool) error {
	// Ensure the host group exists
	groupID, err := c.ensureHostGroup(ctx, c.cfg.Naming.GroupName)
	if err != nil {
		return fmt.Errorf("failed to ensure Vulners host group: %w", err)
	}

	// Get or create the Vulners template
	templateID, err := c.ensureVulnersTemplate(ctx, groupID, force)
	if err != nil {
		return fmt.Errorf("failed to ensure Vulners template: %w", err)
	}

	// Create virtual hosts
	virtualHosts := []struct {
		host string
		name string
	}{
		{c.cfg.Naming.HostsHost, c.cfg.Naming.HostsVisibleName},
		{c.cfg.Naming.PackagesHost, c.cfg.Naming.PackagesVisibleName},
		{c.cfg.Naming.BulletinsHost, c.cfg.Naming.BulletinsVisibleName},
		{c.cfg.Naming.StatisticsHost, c.cfg.Naming.StatisticsVisibleName},
	}

	for _, vh := range virtualHosts {
		if err := c.ensureVirtualHost(ctx, vh.host, vh.name, groupID, templateID, force); err != nil {
			return fmt.Errorf("failed to create virtual host %s: %w", vh.host, err)
		}
	}

	c.log.Info("Virtual hosts ready")
	return nil
}

// ensureVirtualHost creates a virtual host if it doesn't exist.
// When force is true, an existing host is updated with current template linkage and macros.
func (c *Client) ensureVirtualHost(ctx context.Context, host, name, groupID, templateID string, force bool) error {
	// Check if host exists
	params := map[string]interface{}{
		"output": []string{"hostid", "host"},
		"filter": map[string]interface{}{
			"host": host,
		},
	}

	result, err := c.callWithContext(ctx, "host.get", params)
	if err != nil {
		return err
	}

	hosts, err := parseHosts(result)
	if err != nil {
		return err
	}

	if len(hosts) > 0 {
		if force {
			c.log.Info("Force-updating virtual host", slog.String("host", host))
			updateParams := map[string]interface{}{
				"hostid": hosts[0].HostID,
				"templates": []map[string]string{
					{"templateid": templateID},
				},
				"macros": []map[string]string{
					{"macro": "{$SCORE.MIN}", "value": fmt.Sprintf("%g", c.cfg.Scan.MinCVSS)},
				},
			}
			_, err = c.callWithContext(ctx, "host.update", updateParams)
			if err != nil {
				return fmt.Errorf("failed to update host: %w", err)
			}
			return nil
		}
		c.log.Debug("Virtual host already exists", slog.String("host", host))
		return nil
	}

	// Create host with agent interface (required by Zabbix but not used)
	createParams := map[string]interface{}{
		"host": host,
		"name": name,
		"groups": []map[string]string{
			{"groupid": groupID},
		},
		"templates": []map[string]string{
			{"templateid": templateID},
		},
		"interfaces": []map[string]interface{}{
			{
				"type":  1, // agent
				"main":  1,
				"useip": 1,
				"ip":    "127.0.0.1",
				"dns":   c.cfg.Zabbix.ServerFQDN,
				"port":  "10050",
			},
		},
		"macros": []map[string]string{
			{"macro": "{$SCORE.MIN}", "value": fmt.Sprintf("%g", c.cfg.Scan.MinCVSS)},
		},
	}

	_, err = c.callWithContext(ctx, "host.create", createParams)
	if err != nil {
		return fmt.Errorf("failed to create host: %w", err)
	}

	c.log.Info("Created virtual host", slog.String("host", host))
	return nil
}

// ensureTemplateGroup ensures a template group exists (Zabbix >= 6.2) and returns its ID.
func (c *Client) ensureTemplateGroup(ctx context.Context, name string) (string, error) {
	params := map[string]interface{}{
		"output": []string{"groupid"},
		"filter": map[string]interface{}{
			"name": name,
		},
	}

	result, err := c.callWithContext(ctx, "templategroup.get", params)
	if err != nil {
		return "", fmt.Errorf("failed to get template group: %w", err)
	}

	groups, err := parseHostGroups(result)
	if err != nil {
		return "", err
	}

	if len(groups) > 0 {
		return groups[0].GroupID, nil
	}

	createParams := map[string]interface{}{
		"name": name,
	}

	result, err = c.callWithContext(ctx, "templategroup.create", createParams)
	if err != nil {
		return "", fmt.Errorf("failed to create template group: %w", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected response type: %T", result)
	}

	groupIDs, ok := resultMap["groupids"].([]interface{})
	if !ok || len(groupIDs) == 0 {
		return "", fmt.Errorf("no groupid in response")
	}

	groupID, ok := groupIDs[0].(string)
	if !ok {
		return "", fmt.Errorf("unexpected groupid type: %T", groupIDs[0])
	}
	return groupID, nil
}

// ensureVulnersTemplate creates the Vulners template for virtual hosts.
// When force is true and the template already exists, its discovery rules
// and items are deleted and recreated to pick up key schema changes.
func (c *Client) ensureVulnersTemplate(ctx context.Context, groupID string, force bool) (string, error) {
	templateName := c.cfg.Naming.GroupName

	// Check if template exists
	params := map[string]interface{}{
		"output": []string{"templateid", "host"},
		"filter": map[string]interface{}{
			"host": templateName,
		},
	}

	result, err := c.callWithContext(ctx, "template.get", params)
	if err != nil {
		return "", err
	}

	templates, err := parseTemplates(result)
	if err != nil {
		return "", err
	}

	if len(templates) > 0 {
		templateID := templates[0].TemplateID
		if force {
			c.log.Info("Force mode: recreating Vulners template items")
			// Delete all discovery rules (cascades to item/trigger prototypes)
			if err := c.deleteTemplateDiscoveryRules(ctx, templateID); err != nil {
				c.log.Warn("Failed to delete discovery rules", slog.Any("error", err))
			}
			// Delete all plain items
			if err := c.deleteTemplateItems(ctx, templateID); err != nil {
				c.log.Warn("Failed to delete template items", slog.Any("error", err))
			}
			// Recreate everything
			if err := c.createVulnersTemplateItems(ctx, templateID); err != nil {
				return "", err
			}
		}
		return templateID, nil
	}

	// For Zabbix >= 6.2, templates use templategroup API instead of hostgroup
	templateGroupID := groupID
	if c.getAPIVersionFloat() >= 6.2 {
		tgID, err := c.ensureTemplateGroup(ctx, c.cfg.Naming.GroupName)
		if err != nil {
			c.log.Warn("Failed to create template group, falling back to host group", slog.Any("error", err))
		} else {
			templateGroupID = tgID
		}
	}

	// Create template
	createParams := map[string]interface{}{
		"host": templateName,
		"name": "Vulners - Zabbix Threat Control",
		"groups": []map[string]string{
			{"groupid": templateGroupID},
		},
	}

	result, err = c.callWithContext(ctx, "template.create", createParams)
	if err != nil {
		return "", fmt.Errorf("failed to create template: %w", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected response type: %T", result)
	}

	templateIDs, ok := resultMap["templateids"].([]interface{})
	if !ok || len(templateIDs) == 0 {
		return "", fmt.Errorf("no templateid in response")
	}

	templateID, ok := templateIDs[0].(string)
	if !ok {
		return "", fmt.Errorf("unexpected templateid type: %T", templateIDs[0])
	}

	// Create LLD rules and items
	if err := c.createVulnersTemplateItems(ctx, templateID); err != nil {
		return "", err
	}

	c.log.Info("Created Vulners template")
	return templateID, nil
}

// deleteTemplateDiscoveryRules deletes all discovery rules on a template.
// This cascades to item prototypes and trigger prototypes.
func (c *Client) deleteTemplateDiscoveryRules(ctx context.Context, templateID string) error {
	params := map[string]interface{}{
		"output":  []string{"itemid"},
		"hostids": templateID,
	}
	result, err := c.callWithContext(ctx, "discoveryrule.get", params)
	if err != nil {
		return err
	}

	items, ok := result.([]interface{})
	if !ok || len(items) == 0 {
		return nil
	}

	var ids []string
	for _, item := range items {
		if m, ok := item.(map[string]interface{}); ok {
			if id, ok := m["itemid"].(string); ok {
				ids = append(ids, id)
			}
		}
	}

	if len(ids) > 0 {
		_, err = c.callWithContext(ctx, "discoveryrule.delete", ids)
		if err != nil {
			return fmt.Errorf("failed to delete discovery rules: %w", err)
		}
		c.log.Debug("Deleted discovery rules", slog.Int("count", len(ids)))
	}
	return nil
}

// deleteTemplateItems deletes all plain items on a template.
func (c *Client) deleteTemplateItems(ctx context.Context, templateID string) error {
	params := map[string]interface{}{
		"output":      []string{"itemid"},
		"templateids": templateID,
	}
	result, err := c.callWithContext(ctx, "item.get", params)
	if err != nil {
		return err
	}

	items, err := parseItems(result)
	if err != nil {
		return err
	}

	if len(items) == 0 {
		return nil
	}

	var ids []string
	for _, item := range items {
		ids = append(ids, item.ItemID)
	}

	_, err = c.callWithContext(ctx, "item.delete", ids)
	if err != nil {
		return fmt.Errorf("failed to delete items: %w", err)
	}
	c.log.Debug("Deleted template items", slog.Int("count", len(ids)))
	return nil
}

// createVulnersTemplateItems creates LLD rules and items for the Vulners template
func (c *Client) createVulnersTemplateItems(ctx context.Context, templateID string) error {
	// Create LLD rule for hosts
	lldRules := []map[string]interface{}{
		{
			"hostid":   templateID,
			"name":     "Vulners - Hosts Discovery",
			"key_":     "vulners.hosts_lld",
			"type":     2, // Zabbix trapper
			"delay":    "0",
			"lifetime": "0",
		},
		{
			"hostid":   templateID,
			"name":     "Vulners - Packages Discovery",
			"key_":     "vulners.packages_lld",
			"type":     2, // Zabbix trapper
			"delay":    "0",
			"lifetime": "0",
		},
		{
			"hostid":   templateID,
			"name":     "Vulners - Bulletins Discovery",
			"key_":     "vulners.bulletins_lld",
			"type":     2, // Zabbix trapper
			"delay":    "0",
			"lifetime": "0",
		},
	}

	// Map LLD rule key → rule ID for creating item prototypes
	lldRuleIDs := make(map[string]string)
	for _, rule := range lldRules {
		result, err := c.callWithContext(ctx, "discoveryrule.create", rule)
		if err != nil {
			// Rule may already exist — fetch its ID
			c.log.Debug("LLD rule create failed, fetching existing", slog.Any("rule", rule["name"]))
			getParams := map[string]interface{}{
				"output":  []string{"itemid"},
				"hostids": templateID,
				"filter": map[string]interface{}{
					"key_": rule["key_"],
				},
			}
			existing, getErr := c.callWithContext(ctx, "discoveryrule.get", getParams)
			if getErr == nil {
				if items, ok := existing.([]interface{}); ok && len(items) > 0 {
					if item, ok := items[0].(map[string]interface{}); ok {
						if id, ok := item["itemid"].(string); ok {
							lldRuleIDs[rule["key_"].(string)] = id
						}
					}
				}
			}
			continue
		}
		if resultMap, ok := result.(map[string]interface{}); ok {
			if ids, ok := resultMap["itemids"].([]interface{}); ok && len(ids) > 0 {
				if id, ok := ids[0].(string); ok {
					lldRuleIDs[rule["key_"].(string)] = id
				}
			}
		}
	}

	// Create item prototypes for each LLD rule so that discovered entities
	// produce actual trapper items that accept score data.
	type itemProto struct {
		ruleKey string
		name    string
		key     string
	}
	prototypes := []itemProto{
		{"vulners.hosts_lld", "Host {#H.VNAME} CVSS Score", "vulners.hosts[{#H.ID}]"},
		{"vulners.packages_lld", "Package {#P.NAME} {#P.VERSION} ({#P.ARCH}) CVSS Score", "vulners.packages[{#P.NAME},{#P.VERSION},{#P.ARCH}]"},
		{"vulners.bulletins_lld", "Bulletin {#B.ID} CVSS Score", "vulners.bulletins[{#B.ID}]"},
	}
	for _, proto := range prototypes {
		ruleID, ok := lldRuleIDs[proto.ruleKey]
		if !ok {
			continue
		}
		protoParams := map[string]interface{}{
			"hostid":     templateID,
			"ruleid":     ruleID,
			"name":       proto.name,
			"key_":       proto.key,
			"type":       2, // Zabbix trapper
			"value_type": 0, // numeric float
			"delay":      "0",
		}
		_, err := c.callWithContext(ctx, "itemprototype.create", protoParams)
		if err != nil {
			c.log.Warn("Failed to create item prototype (may already exist)", slog.String("prototype", proto.key))
		}
	}

	// Create trapper items for statistics — Python-compatible keys.
	// value_type 3 = numeric unsigned (for integer values: counts).
	// value_type 0 = numeric float (for CVSS scores: preserves decimals).
	// Note: Python used value_type=3 for ALL stats items (including scores),
	// which truncates float CVSS values. We intentionally use value_type=0
	// for score items to preserve precision.
	statItems := []map[string]interface{}{
		{"hostid": templateID, "name": "CVSS Score - Total Hosts", "key_": "vulners.TotalHosts", "type": 2, "value_type": 3},
		{"hostid": templateID, "name": "CVSS Score - Maximum", "key_": "vulners.Maximum", "type": 2, "value_type": 0},
		{"hostid": templateID, "name": "CVSS Score - Average", "key_": "vulners.Average", "type": 2, "value_type": 0},
		{"hostid": templateID, "name": "CVSS Score - Minimum", "key_": "vulners.Minimum", "type": 2, "value_type": 0},
		{"hostid": templateID, "name": "CVSS Score - Median", "key_": "vulners.scoreMedian", "type": 2, "value_type": 0},
	}

	// Histogram bucket items (Python-compatible: value_type=3 for integer counts)
	for i := 0; i <= 10; i++ {
		statItems = append(statItems, map[string]interface{}{
			"hostid":     templateID,
			"name":       fmt.Sprintf("CVSS Score - Hosts with a score ~ %d", i),
			"key_":       fmt.Sprintf("vulners.hostsCountScore%d", i),
			"type":       2,
			"value_type": 3, // numeric unsigned (host count)
		})
	}

	// Go backward-compatible stat items
	goStatItems := []map[string]interface{}{
		{"hostid": templateID, "name": "Vulners - Total Hosts", "key_": "vulners.stats[total_hosts]", "type": 2, "value_type": 3},
		{"hostid": templateID, "name": "Vulners - Vulnerable Hosts", "key_": "vulners.stats[vuln_hosts]", "type": 2, "value_type": 3},
		{"hostid": templateID, "name": "Vulners - Total Vulnerabilities", "key_": "vulners.stats[total_vulns]", "type": 2, "value_type": 3},
		{"hostid": templateID, "name": "Vulners - Max CVSS Score", "key_": "vulners.stats[max_score]", "type": 2, "value_type": 0},
		{"hostid": templateID, "name": "Vulners - Total Bulletins", "key_": "vulners.stats[total_bulletins]", "type": 2, "value_type": 3},
		{"hostid": templateID, "name": "Vulners - Total CVEs", "key_": "vulners.stats[total_cves]", "type": 2, "value_type": 3},
		{"hostid": templateID, "name": "Vulners - Average CVSS Score", "key_": "vulners.stats[avg_score]", "type": 2, "value_type": 0},
	}
	statItems = append(statItems, goStatItems...)

	for _, item := range statItems {
		_, err := c.callWithContext(ctx, "item.create", item)
		if err != nil {
			c.log.Warn("Failed to create item (may already exist)", slog.Any("item", item["name"]))
		}
	}

	// Create trigger prototypes for alerting
	if err := c.createTriggerPrototypes(ctx, lldRuleIDs); err != nil {
		c.log.Warn("Failed to create some trigger prototypes", slog.Any("error", err))
	}

	return nil
}

// createTriggerPrototypes creates version-aware trigger prototypes for all LLD rules.
func (c *Client) createTriggerPrototypes(ctx context.Context, lldRuleIDs map[string]string) error {
	version := c.getAPIVersionFloat()

	type triggerDef struct {
		ruleKey     string
		expression  string
		description string
		url         string
		comments    string
	}

	var triggers []triggerDef

	if version < 5.4 {
		// Legacy syntax: {host:key.last()}
		triggers = []triggerDef{
			{
				ruleKey:     "vulners.hosts_lld",
				expression:  fmt.Sprintf("{%s:vulners.hosts[{#H.ID}].last()} > 0 and {#H.SCORE} >= {$SCORE.MIN}", c.cfg.Naming.HostsHost),
				description: "Score {#H.SCORE}. Host = {#H.VNAME}",
				url:         "",
				comments:    "Cumulative fix:\r\n\r\n{#H.FIX}",
			},
			{
				ruleKey:     "vulners.bulletins_lld",
				expression:  fmt.Sprintf("{%s:vulners.bulletins[{#BULLETIN.ID}].last()} > 0 and {#BULLETIN.SCORE} >= {$SCORE.MIN}", c.cfg.Naming.BulletinsHost),
				description: "Impact {#BULLETIN.IMPACT}. Score {#BULLETIN.SCORE}. Affected {ITEM.VALUE}. Bulletin = {#BULLETIN.ID}",
				url:         "https://vulners.com/info/{#BULLETIN.ID}",
				comments:    "Vulnerabilities are found on:\r\n\r\n{#BULLETIN.HOSTS}",
			},
			{
				ruleKey:     "vulners.packages_lld",
				expression:  fmt.Sprintf("{%s:vulners.packages[{#P.NAME},{#P.VERSION},{#P.ARCH}].last()} > 0 and {#PKG.SCORE} >= {$SCORE.MIN}", c.cfg.Naming.PackagesHost),
				description: "Impact {#PKG.IMPACT}. Score {#PKG.SCORE}. Affected {ITEM.VALUE}. Package = {#PKG.ID}",
				url:         "https://vulners.com/info/{#PKG.URL}",
				comments:    "Vulnerabilities are found on:\r\n\r\n{#PKG.HOSTS}\r\n----\r\n{#PKG.FIX}",
			},
		}
	} else {
		// New syntax: last(/host/key)
		triggers = []triggerDef{
			{
				ruleKey:     "vulners.hosts_lld",
				expression:  fmt.Sprintf("last(/%s/vulners.hosts[{#H.ID}]) > 0 and {#H.SCORE} >= {$SCORE.MIN}", c.cfg.Naming.HostsHost),
				description: "Score {#H.SCORE}. Host = {#H.VNAME}",
				url:         "",
				comments:    "Cumulative fix:\r\n\r\n{#H.FIX}",
			},
			{
				ruleKey:     "vulners.bulletins_lld",
				expression:  fmt.Sprintf("last(/%s/vulners.bulletins[{#BULLETIN.ID}]) > 0 and {#BULLETIN.SCORE} >= {$SCORE.MIN}", c.cfg.Naming.BulletinsHost),
				description: "Impact {#BULLETIN.IMPACT}. Score {#BULLETIN.SCORE}. Affected {ITEM.VALUE}. Bulletin = {#BULLETIN.ID}",
				url:         "https://vulners.com/info/{#BULLETIN.ID}",
				comments:    "Vulnerabilities are found on:\r\n\r\n{#BULLETIN.HOSTS}",
			},
			{
				ruleKey:     "vulners.packages_lld",
				expression:  fmt.Sprintf("last(/%s/vulners.packages[{#P.NAME},{#P.VERSION},{#P.ARCH}]) > 0 and {#PKG.SCORE} >= {$SCORE.MIN}", c.cfg.Naming.PackagesHost),
				description: "Impact {#PKG.IMPACT}. Score {#PKG.SCORE}. Affected {ITEM.VALUE}. Package = {#PKG.ID}",
				url:         "https://vulners.com/info/{#PKG.URL}",
				comments:    "Vulnerabilities are found on:\r\n\r\n{#PKG.HOSTS}\r\n----\r\n{#PKG.FIX}",
			},
		}
	}

	for _, trig := range triggers {
		if _, ok := lldRuleIDs[trig.ruleKey]; !ok {
			continue
		}
		params := map[string]interface{}{
			"expression":   trig.expression,
			"description":  trig.description,
			"url":          trig.url,
			"manual_close": 1,
			"priority":     "0",
			"comments":     trig.comments,
			"status":       "0",
		}
		_, err := c.callWithContext(ctx, "triggerprototype.create", params)
		if err != nil {
			c.log.Warn("Failed to create trigger prototype (may already exist)", slog.String("trigger", trig.description))
		}
	}

	return nil
}

// EnsureDashboard creates the Vulners dashboard
func (c *Client) EnsureDashboard() error {
	return c.EnsureDashboardCtx(context.Background(), false)
}

// EnsureDashboardCtx creates the Vulners dashboard with context.
// It also creates statistics graphs on the statistics virtual host.
// When force is true, an existing dashboard is deleted and recreated.
func (c *Client) EnsureDashboardCtx(ctx context.Context, force bool) error {
	// Create statistics graphs (requires statistics host items to exist)
	medianGraphID, scoreGraphID, err := c.createStatisticsGraphs(ctx)
	if err != nil {
		c.log.Warn("Failed to create statistics graphs", slog.Any("error", err))
	}

	dashboardName := c.cfg.Naming.DashboardName

	// Check if dashboard exists
	params := map[string]interface{}{
		"output": []string{"dashboardid", "name"},
		"filter": map[string]interface{}{
			"name": dashboardName,
		},
	}

	result, err := c.callWithContext(ctx, "dashboard.get", params)
	if err != nil {
		return err
	}

	dashboards, ok := result.([]interface{})
	if !ok {
		return fmt.Errorf("unexpected response type: %T", result)
	}

	if len(dashboards) > 0 {
		if force {
			// Delete existing dashboard and recreate
			if dm, ok := dashboards[0].(map[string]interface{}); ok {
				if dashID, ok := dm["dashboardid"].(string); ok {
					c.log.Info("Force mode: deleting existing dashboard")
					_, err = c.callWithContext(ctx, "dashboard.delete", []string{dashID})
					if err != nil {
						return fmt.Errorf("failed to delete dashboard: %w", err)
					}
				}
			}
		} else {
			c.log.Info("Dashboard already exists")
			return nil
		}
	}

	// Resolve virtual host IDs for dashboard widgets
	hostsHostID := c.resolveHostID(ctx, c.cfg.Naming.HostsHost)
	packagesHostID := c.resolveHostID(ctx, c.cfg.Naming.PackagesHost)
	bulletinsHostID := c.resolveHostID(ctx, c.cfg.Naming.BulletinsHost)

	// Build widgets
	widgets := []map[string]interface{}{
		{
			"type": "problems", "name": "Vulners - Hosts",
			"x": 0, "y": 8, "width": 8, "height": 8,
			"fields": []map[string]interface{}{
				{"type": 0, "name": "rf_rate", "value": "600"},
				{"type": 0, "name": "show", "value": "3"},
				{"type": 0, "name": "show_lines", "value": "100"},
				{"type": 0, "name": "sort_triggers", "value": "16"},
				{"type": 3, "name": "hostids", "value": hostsHostID},
			},
		},
		{
			"type": "problems", "name": "Vulners - Packages",
			"x": 8, "y": 0, "width": 8, "height": 8,
			"fields": []map[string]interface{}{
				{"type": 0, "name": "rf_rate", "value": "600"},
				{"type": 0, "name": "show", "value": "3"},
				{"type": 0, "name": "show_lines", "value": "100"},
				{"type": 0, "name": "sort_triggers", "value": "16"},
				{"type": 3, "name": "hostids", "value": packagesHostID},
			},
		},
		{
			"type": "problems", "name": "Vulners - Bulletins",
			"x": 8, "y": 8, "width": 8, "height": 8,
			"fields": []map[string]interface{}{
				{"type": 0, "name": "rf_rate", "value": "900"},
				{"type": 0, "name": "show", "value": "3"},
				{"type": 0, "name": "show_lines", "value": "100"},
				{"type": 0, "name": "sort_triggers", "value": "16"},
				{"type": 3, "name": "hostids", "value": bulletinsHostID},
			},
		},
	}

	// Add graph widgets if graphs were created
	if scoreGraphID != "" {
		widgets = append(widgets, map[string]interface{}{
			"type": "graph", "name": "CVSS Score ratio by servers",
			"x": 0, "y": 0, "width": 8, "height": 4,
			"fields": []map[string]interface{}{
				{"type": 0, "name": "rf_rate", "value": "600"},
				{"type": 0, "name": "show_legend", "value": "0"},
				{"type": 6, "name": "graphid", "value": scoreGraphID},
			},
		})
	}
	if medianGraphID != "" {
		widgets = append(widgets, map[string]interface{}{
			"type": "graph", "name": "Median CVSS Score",
			"x": 0, "y": 4, "width": 8, "height": 4,
			"fields": []map[string]interface{}{
				{"type": 0, "name": "rf_rate", "value": "600"},
				{"type": 0, "name": "show_legend", "value": "0"},
				{"type": 6, "name": "graphid", "value": medianGraphID},
			},
		})
	}

	// Create dashboard
	createParams := map[string]interface{}{
		"name":           dashboardName,
		"display_period": 30,
		"auto_start":     1,
	}

	if c.getAPIVersionFloat() > 5.0 {
		createParams["pages"] = []map[string]interface{}{
			{"widgets": widgets},
		}
	} else {
		createParams["widgets"] = widgets
	}

	_, err = c.callWithContext(ctx, "dashboard.create", createParams)
	if err != nil {
		return fmt.Errorf("failed to create dashboard: %w", err)
	}

	c.log.Info("Created dashboard")
	return nil
}

// resolveHostID looks up the Zabbix host ID for a virtual host by technical name.
func (c *Client) resolveHostID(ctx context.Context, techName string) string {
	params := map[string]interface{}{
		"output": []string{"hostid"},
		"filter": map[string]interface{}{"host": techName},
	}
	result, err := c.callWithContext(ctx, "host.get", params)
	if err != nil {
		return ""
	}
	hosts, err := parseHosts(result)
	if err != nil || len(hosts) == 0 {
		return ""
	}
	return hosts[0].HostID
}

// createStatisticsGraphs creates the median CVSS and score-ratio graphs on the
// statistics virtual host. Returns (medianGraphID, scoreGraphID, error).
func (c *Client) createStatisticsGraphs(ctx context.Context) (string, string, error) {
	// Resolve statistics host ID
	statisticsHostID := c.resolveHostID(ctx, c.cfg.Naming.StatisticsHost)
	if statisticsHostID == "" {
		return "", "", fmt.Errorf("statistics virtual host not found")
	}

	// Helper to find an item ID by key on a host
	findItem := func(key string) string {
		params := map[string]interface{}{
			"output":  []string{"itemid"},
			"hostids": statisticsHostID,
			"filter":  map[string]interface{}{"key_": key},
		}
		result, err := c.callWithContext(ctx, "item.get", params)
		if err != nil {
			return ""
		}
		items, err := parseItems(result)
		if err != nil || len(items) == 0 {
			return ""
		}
		return items[0].ItemID
	}

	// Check if graphs already exist
	for _, name := range []string{"Median CVSS Score", "CVSS Score ratio by servers"} {
		params := map[string]interface{}{
			"output":  []string{"graphid"},
			"hostids": statisticsHostID,
			"filter":  map[string]interface{}{"name": name},
		}
		result, err := c.callWithContext(ctx, "graph.get", params)
		if err == nil {
			if graphs, ok := result.([]interface{}); ok && len(graphs) > 0 {
				c.log.Debug("Graph already exists", slog.String("graph", name))
			}
		}
	}

	// Graph 1: Median CVSS Score (line graph)
	medianItemID := findItem("vulners.scoreMedian")
	var medianGraphID string
	if medianItemID != "" {
		params := map[string]interface{}{
			"name":             "Median CVSS Score",
			"width":            1000,
			"height":           300,
			"show_work_period": 0,
			"graphtype":        0, // normal
			"show_legend":      0,
			"show_3d":          0,
			"gitems": []map[string]interface{}{
				{"itemid": medianItemID, "color": "00AAAA", "drawtype": "5"},
			},
		}
		result, err := c.callWithContext(ctx, "graph.create", params)
		if err != nil {
			c.log.Warn("Failed to create median CVSS graph (may already exist)", slog.Any("error", err))
		} else if resultMap, ok := result.(map[string]interface{}); ok {
			if ids, ok := resultMap["graphids"].([]interface{}); ok && len(ids) > 0 {
				if id, ok := ids[0].(string); ok {
					medianGraphID = id
				}
			}
		}
	}

	// Graph 2: CVSS Score ratio by servers (pie chart)
	colors := []string{"DD0000", "EE0000", "FF3333", "EEEE00", "FFFF66", "00EEEE", "00DDDD", "3333FF", "6666FF", "00DD00", "33FF33"}
	var gitems []map[string]interface{}
	for i := 0; i <= 10; i++ {
		itemID := findItem(fmt.Sprintf("vulners.hostsCountScore%d", i))
		if itemID == "" {
			continue
		}
		gitems = append(gitems, map[string]interface{}{
			"itemid":   itemID,
			"color":    colors[i],
			"drawtype": "5",
			"calc_fnc": "9",
		})
	}

	var scoreGraphID string
	if len(gitems) == 11 {
		params := map[string]interface{}{
			"name":             "CVSS Score ratio by servers",
			"width":            1000,
			"height":           300,
			"show_work_period": 0,
			"graphtype":        2, // pie
			"show_legend":      0,
			"show_3d":          1,
			"gitems":           gitems,
		}
		result, err := c.callWithContext(ctx, "graph.create", params)
		if err != nil {
			c.log.Warn("Failed to create score ratio graph (may already exist)", slog.Any("error", err))
		} else if resultMap, ok := result.(map[string]interface{}); ok {
			if ids, ok := resultMap["graphids"].([]interface{}); ok && len(ids) > 0 {
				if id, ok := ids[0].(string); ok {
					scoreGraphID = id
				}
			}
		}
	} else {
		c.log.Warn("Not all histogram items found, skipping score ratio graph")
	}

	return medianGraphID, scoreGraphID, nil
}

// EnsureActions creates actions for vulnerability alerts
func (c *Client) EnsureActions() error {
	return c.EnsureActionsCtx(context.Background())
}

// EnsureActionsCtx creates actions with context
func (c *Client) EnsureActionsCtx(ctx context.Context) error {
	actionName := c.cfg.Naming.ActionName

	// Check if action exists
	params := map[string]interface{}{
		"output": []string{"actionid", "name"},
		"filter": map[string]interface{}{
			"name": actionName,
		},
	}

	result, err := c.callWithContext(ctx, "action.get", params)
	if err != nil {
		return err
	}

	actions, ok := result.([]interface{})
	if !ok {
		return fmt.Errorf("unexpected response type: %T", result)
	}

	if len(actions) > 0 {
		c.log.Info("Action already exists")
		return nil
	}

	c.log.Info("Action creation requires manual configuration in Zabbix UI")
	return nil
}
