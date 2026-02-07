package zabbix

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// EnsureOSReportTemplate creates or updates the OS-Report template
func (c *Client) EnsureOSReportTemplate() error {
	return c.EnsureOSReportTemplateCtx(context.Background(), false)
}

// EnsureOSReportTemplateCtx creates or updates the OS-Report template with context.
// When force is true, existing template items are refreshed.
func (c *Client) EnsureOSReportTemplateCtx(ctx context.Context, force bool) error {
	// Check if template exists
	templateParams := map[string]interface{}{
		"output": []string{"templateid", "host", "name"},
		"filter": map[string]interface{}{
			"host": c.cfg.Scan.OSReportTemplate,
		},
	}

	result, err := c.callWithContext(ctx, "template.get", templateParams)
	if err != nil {
		return fmt.Errorf("failed to check template: %w", err)
	}

	templates, err := parseTemplates(result)
	if err != nil {
		return err
	}

	if len(templates) > 0 {
		c.log.Info("OS-Report template already exists")
		return c.updateOSReportItems(ctx, templates[0].TemplateID)
	}

	// Create template
	c.log.Info("Creating OS-Report template")

	// First get or create a host group for the template
	groupID, err := c.ensureHostGroup(ctx, c.cfg.Scan.TemplateGroupName)
	if err != nil {
		return err
	}

	createParams := map[string]interface{}{
		"host": c.cfg.Scan.OSReportTemplate,
		"name": c.cfg.Scan.OSReportVisibleName,
		"groups": []map[string]string{
			{"groupid": groupID},
		},
	}

	result, err = c.callWithContext(ctx, "template.create", createParams)
	if err != nil {
		return fmt.Errorf("failed to create template: %w", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected response type: %T", result)
	}

	templateIDs, ok := resultMap["templateids"].([]interface{})
	if !ok || len(templateIDs) == 0 {
		return fmt.Errorf("no templateid in response")
	}

	templateID, ok := templateIDs[0].(string)
	if !ok {
		return fmt.Errorf("unexpected templateid type: %T", templateIDs[0])
	}
	return c.createOSReportItems(ctx, templateID)
}

// createOSReportItems creates the items for the OS-Report template
func (c *Client) createOSReportItems(ctx context.Context, templateID string) error {
	items := []map[string]interface{}{
		{
			"hostid":      templateID,
			"name":        "OS - Name",
			"key_":        "system.sw.os",
			"type":        0, // Zabbix agent
			"value_type":  1, // text
			"delay":       "1d",
			"description": "Operating system name and version",
		},
		{
			"hostid":      templateID,
			"name":        "OS - Packages",
			"key_":        "system.sw.packages",
			"type":        0, // Zabbix agent
			"value_type":  4, // text
			"delay":       "1d",
			"description": "List of installed packages",
		},
	}

	for _, item := range items {
		_, err := c.callWithContext(ctx, "item.create", item)
		if err != nil {
			return fmt.Errorf("failed to create item %s: %w", item["name"], err)
		}
	}

	c.log.Info("Created OS-Report template items")
	return nil
}

// updateOSReportItems ensures the items exist on an existing template
func (c *Client) updateOSReportItems(ctx context.Context, templateID string) error {
	// Get existing items
	itemParams := map[string]interface{}{
		"output":      []string{"itemid", "key_"},
		"templateids": templateID,
	}

	result, err := c.callWithContext(ctx, "item.get", itemParams)
	if err != nil {
		return fmt.Errorf("failed to get template items: %w", err)
	}

	items, err := parseItems(result)
	if err != nil {
		return err
	}

	// Check if required items exist
	requiredKeys := map[string]bool{
		"system.sw.os":       false,
		"system.sw.packages": false,
	}

	for _, item := range items {
		if _, exists := requiredKeys[item.Key]; exists {
			requiredKeys[item.Key] = true
		}
	}

	// Create missing items
	for key, exists := range requiredKeys {
		if !exists {
			c.log.Info("Creating missing template item", zap.String("key", key))
			// Create the missing item
			itemDef := map[string]interface{}{
				"hostid":     templateID,
				"key_":       key,
				"type":       0,
				"value_type": 1,
				"delay":      "1d",
			}
			switch key {
			case "system.sw.os":
				itemDef["name"] = "OS - Name"
			case "system.sw.packages":
				itemDef["name"] = "OS - Packages"
				itemDef["value_type"] = 4
			}
			_, err := c.callWithContext(ctx, "item.create", itemDef)
			if err != nil {
				return fmt.Errorf("failed to create item %s: %w", key, err)
			}
		}
	}

	return nil
}

// ensureHostGroup ensures a host group exists and returns its ID
func (c *Client) ensureHostGroup(ctx context.Context, name string) (string, error) {
	// Check if group exists
	params := map[string]interface{}{
		"output": []string{"groupid", "name"},
		"filter": map[string]interface{}{
			"name": name,
		},
	}

	result, err := c.callWithContext(ctx, "hostgroup.get", params)
	if err != nil {
		return "", fmt.Errorf("failed to get host group: %w", err)
	}

	groups, err := parseHostGroups(result)
	if err != nil {
		return "", err
	}

	if len(groups) > 0 {
		return groups[0].GroupID, nil
	}

	// Create group
	createParams := map[string]interface{}{
		"name": name,
	}

	result, err = c.callWithContext(ctx, "hostgroup.create", createParams)
	if err != nil {
		return "", fmt.Errorf("failed to create host group: %w", err)
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

// parseHostGroups parses the API response into a slice of HostGroup
func parseHostGroups(result interface{}) ([]HostGroup, error) {
	groups, ok := result.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", result)
	}

	var hostGroups []HostGroup
	for _, g := range groups {
		gMap, ok := g.(map[string]interface{})
		if !ok {
			continue
		}
		groupID, ok := gMap["groupid"].(string)
		if !ok {
			continue
		}
		name, ok := gMap["name"].(string)
		if !ok {
			continue
		}
		hostGroups = append(hostGroups, HostGroup{
			GroupID: groupID,
			Name:    name,
		})
	}

	return hostGroups, nil
}
