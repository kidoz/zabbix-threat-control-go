package zabbix

import (
	"context"
	"encoding/json"
	"fmt"
)

// GetHostsWithTemplate returns all hosts that have the specified template
func (c *Client) GetHostsWithTemplate(templateName string) ([]Host, error) {
	return c.GetHostsWithTemplateCtx(context.Background(), templateName)
}

// GetHostsWithTemplateCtx returns hosts with the specified template using context
func (c *Client) GetHostsWithTemplateCtx(ctx context.Context, templateName string) ([]Host, error) {
	// First, get the template ID
	templateParams := map[string]interface{}{
		"output": []string{"templateid", "host", "name"},
		"filter": map[string]interface{}{
			"host": templateName,
		},
	}

	result, err := c.callWithContext(ctx, "template.get", templateParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	templates, err := parseTemplates(result)
	if err != nil {
		return nil, err
	}

	if len(templates) == 0 {
		return nil, fmt.Errorf("template not found: %s", templateName)
	}

	templateID := templates[0].TemplateID

	// Get hosts linked to this template (only monitored hosts, matching Python behavior)
	hostParams := map[string]interface{}{
		"output":                []string{"hostid", "host", "name", "status"},
		"templateids":           templateID,
		"monitored_hosts":       true,
		"selectInterfaces":      []string{"interfaceid", "ip", "dns", "port", "type", "main", "useip"},
		"selectGroups":          []string{"groupid", "name"},
		"selectParentTemplates": []string{"templateid", "host", "name"},
	}

	result, err = c.callWithContext(ctx, "host.get", hostParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get hosts: %w", err)
	}

	return parseHosts(result)
}

// GetHostByID returns a host by its ID
func (c *Client) GetHostByID(hostID string) (*Host, error) {
	return c.GetHostByIDCtx(context.Background(), hostID)
}

// GetHostByIDCtx returns a host by its ID using context
func (c *Client) GetHostByIDCtx(ctx context.Context, hostID string) (*Host, error) {
	params := map[string]interface{}{
		"output":                []string{"hostid", "host", "name", "status"},
		"hostids":               hostID,
		"selectInterfaces":      []string{"interfaceid", "ip", "dns", "port", "type", "main", "useip"},
		"selectGroups":          []string{"groupid", "name"},
		"selectParentTemplates": []string{"templateid", "host", "name"},
	}

	result, err := c.callWithContext(ctx, "host.get", params)
	if err != nil {
		return nil, fmt.Errorf("failed to get host: %w", err)
	}

	hosts, err := parseHosts(result)
	if err != nil {
		return nil, err
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("host not found: %s", hostID)
	}

	return &hosts[0], nil
}

// GetHostByName returns a host by its technical name
func (c *Client) GetHostByName(name string) (*Host, error) {
	return c.GetHostByNameCtx(context.Background(), name)
}

// GetHostByNameCtx returns a host by its technical name using context
func (c *Client) GetHostByNameCtx(ctx context.Context, name string) (*Host, error) {
	params := map[string]interface{}{
		"output":                []string{"hostid", "host", "name", "status"},
		"filter":                map[string]interface{}{"host": name},
		"selectInterfaces":      []string{"interfaceid", "ip", "dns", "port", "type", "main", "useip"},
		"selectGroups":          []string{"groupid", "name"},
		"selectParentTemplates": []string{"templateid", "host", "name"},
	}

	result, err := c.callWithContext(ctx, "host.get", params)
	if err != nil {
		return nil, fmt.Errorf("failed to get host: %w", err)
	}

	hosts, err := parseHosts(result)
	if err != nil {
		return nil, err
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("host not found: %s", name)
	}

	return &hosts[0], nil
}

// GetHostItems returns items for a host by key pattern
func (c *Client) GetHostItems(hostID string, keyPattern string) ([]Item, error) {
	return c.GetHostItemsCtx(context.Background(), hostID, keyPattern)
}

// GetHostItemsCtx returns items for a host by key pattern using context
func (c *Client) GetHostItemsCtx(ctx context.Context, hostID string, keyPattern string) ([]Item, error) {
	params := map[string]interface{}{
		"output":  []string{"itemid", "hostid", "name", "key_", "lastvalue", "value_type", "state"},
		"hostids": hostID,
		"search": map[string]interface{}{
			"key_": keyPattern,
		},
		"searchWildcardsEnabled": true,
	}

	result, err := c.callWithContext(ctx, "item.get", params)
	if err != nil {
		return nil, fmt.Errorf("failed to get items: %w", err)
	}

	return parseItems(result)
}

// CreateHost creates a new host in Zabbix
func (c *Client) CreateHost(host *Host, groupIDs []string, templateIDs []string) (string, error) {
	return c.CreateHostCtx(context.Background(), host, groupIDs, templateIDs)
}

// CreateHostCtx creates a new host with context
func (c *Client) CreateHostCtx(ctx context.Context, host *Host, groupIDs []string, templateIDs []string) (string, error) {
	groups := make([]map[string]string, len(groupIDs))
	for i, gid := range groupIDs {
		groups[i] = map[string]string{"groupid": gid}
	}

	templates := make([]map[string]string, len(templateIDs))
	for i, tid := range templateIDs {
		templates[i] = map[string]string{"templateid": tid}
	}

	params := map[string]interface{}{
		"host":      host.Host,
		"name":      host.Name,
		"groups":    groups,
		"templates": templates,
	}

	if len(host.Interfaces) > 0 {
		params["interfaces"] = host.Interfaces
	}

	result, err := c.callWithContext(ctx, "host.create", params)
	if err != nil {
		return "", fmt.Errorf("failed to create host: %w", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("unexpected response type: %T", result)
	}

	hostIDs, ok := resultMap["hostids"].([]interface{})
	if !ok || len(hostIDs) == 0 {
		return "", fmt.Errorf("no hostid in response")
	}

	hostID, ok := hostIDs[0].(string)
	if !ok {
		return "", fmt.Errorf("unexpected hostid type: %T", hostIDs[0])
	}
	return hostID, nil
}

// parseHosts parses the API response into a slice of Host
func parseHosts(result interface{}) ([]Host, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}

	var hosts []Host
	if err := json.Unmarshal(data, &hosts); err != nil {
		return nil, fmt.Errorf("failed to unmarshal hosts: %w", err)
	}

	return hosts, nil
}

// parseItems parses the API response into a slice of Item
func parseItems(result interface{}) ([]Item, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}

	var items []Item
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("failed to unmarshal items: %w", err)
	}

	return items, nil
}

// parseTemplates parses the API response into a slice of Template
func parseTemplates(result interface{}) ([]Template, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}

	var templates []Template
	if err := json.Unmarshal(data, &templates); err != nil {
		return nil, fmt.Errorf("failed to unmarshal templates: %w", err)
	}

	return templates, nil
}
