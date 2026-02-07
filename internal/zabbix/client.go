package zabbix

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.uber.org/zap"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
)

// Client is a Zabbix API client
type Client struct {
	cfg        *config.Config
	log        *zap.Logger
	httpClient *http.Client
	authToken  string
	apiVersion string
	requestID  int64
}

// NewClient creates a new Zabbix API client
func NewClient(cfg *config.Config, log *zap.Logger) (*Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !cfg.Zabbix.VerifySSL, //nolint:gosec // G402: user-configurable option, defaults to VerifySSL=true
		},
	}

	c := &Client{
		cfg: cfg,
		log: log,
		httpClient: &http.Client{
			Timeout:   time.Duration(cfg.Scan.Timeout) * time.Second,
			Transport: otelhttp.NewTransport(transport),
		},
	}

	// Fetch API version before auth (apiinfo.version does not require auth)
	ver, err := c.GetAPIVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get API version: %w", err)
	}
	c.apiVersion = ver
	c.log.Debug("Detected Zabbix API version", zap.String("version", ver))

	// Authenticate
	if err := c.authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	return c, nil
}

// authenticate logs in to the Zabbix API
func (c *Client) authenticate() error {
	params := map[string]string{
		"user":     c.cfg.Zabbix.APIUser,
		"password": c.cfg.Zabbix.APIPassword,
	}

	result, err := c.call("user.login", params)
	if err != nil {
		return err
	}

	token, ok := result.(string)
	if !ok {
		return fmt.Errorf("unexpected auth response type: %T", result)
	}

	c.authToken = token
	c.log.Debug("Authenticated with Zabbix API")
	return nil
}

// call makes a JSON-RPC call to the Zabbix API
func (c *Client) call(method string, params interface{}) (interface{}, error) {
	return c.callWithContext(context.Background(), method, params)
}

// callWithContext makes a JSON-RPC call with context
func (c *Client) callWithContext(ctx context.Context, method string, params interface{}) (interface{}, error) {
	reqID := atomic.AddInt64(&c.requestID, 1)

	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      reqID,
	}

	// Add auth token if we have one (except for login)
	if c.authToken != "" && method != "user.login" {
		reqBody["auth"] = c.authToken
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	c.log.Debug("Calling Zabbix API", zap.String("method", method), zap.Int64("id", reqID))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ZabbixAPIURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json-rpc")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if apiResp.Error != nil {
		return nil, apiResp.Error
	}

	return apiResp.Result, nil
}

// GetAPIVersion returns the Zabbix API version
func (c *Client) GetAPIVersion() (string, error) {
	result, err := c.call("apiinfo.version", []string{})
	if err != nil {
		return "", err
	}
	version, ok := result.(string)
	if !ok {
		return "", fmt.Errorf("unexpected API version type: %T", result)
	}
	return version, nil
}

// getAPIVersionFloat parses the stored API version string (e.g. "6.4.1") into
// a float like 6.4 for version-aware branching.
func (c *Client) getAPIVersionFloat() float64 {
	parts := strings.SplitN(c.apiVersion, ".", 3)
	if len(parts) >= 2 {
		v, _ := strconv.ParseFloat(parts[0]+"."+parts[1], 64)
		return v
	}
	return 0
}

// GetItemValueCtx retrieves the last value of a specific item by host technical
// name and item key. Returns an empty string if the item doesn't exist.
func (c *Client) GetItemValueCtx(ctx context.Context, hostTechName, itemKey string) (string, error) {
	// Resolve host to hostid
	hostParams := map[string]interface{}{
		"output": []string{"hostid"},
		"filter": map[string]interface{}{
			"host": hostTechName,
		},
	}
	hostResult, err := c.callWithContext(ctx, "host.get", hostParams)
	if err != nil {
		return "", fmt.Errorf("failed to get host %q: %w", hostTechName, err)
	}
	hosts, err := parseHosts(hostResult)
	if err != nil {
		return "", err
	}
	if len(hosts) == 0 {
		return "", fmt.Errorf("host not found: %s", hostTechName)
	}

	items, err := c.GetHostItemsCtx(ctx, hosts[0].HostID, itemKey)
	if err != nil {
		return "", err
	}
	for _, item := range items {
		if item.Key == itemKey {
			return item.Value, nil
		}
	}
	return "", nil
}

// Close logs out from the Zabbix API
func (c *Client) Close() error {
	if c.authToken == "" {
		return nil
	}

	_, err := c.call("user.logout", []string{})
	c.authToken = ""
	return err
}
