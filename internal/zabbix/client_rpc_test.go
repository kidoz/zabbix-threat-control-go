package zabbix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"io"
	"log/slog"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
)

// newTestServer creates an httptest.Server that speaks Zabbix JSON-RPC.
// The handler func receives the decoded method name and params, and returns
// the result value (which gets wrapped in an APIResponse).
func newTestServer(t *testing.T, handler func(method string, params json.RawMessage) (interface{}, *APIError)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			ID     int             `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		result, apiErr := handler(req.Method, req.Params)
		resp := APIResponse{
			JSONRPC: "2.0",
			Result:  result,
			Error:   apiErr,
			ID:      req.ID,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
}

// newTestClient creates a Client backed by the given test server.
// It skips the real authenticate/version calls and sets the authToken directly.
func newTestClient(t *testing.T, ts *httptest.Server) *Client {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Zabbix.FrontURL = ts.URL
	return &Client{
		cfg:        cfg,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		httpClient: ts.Client(),
		authToken:  "test-token",
		apiVersion: "7.0.0",
	}
}

func TestNewClient_AuthenticatesAndFetchesVersion(t *testing.T) {
	var gotMethods []string
	ts := newTestServer(t, func(method string, _ json.RawMessage) (interface{}, *APIError) {
		gotMethods = append(gotMethods, method)
		switch method {
		case "apiinfo.version":
			return "7.0.0", nil
		case "user.login":
			return "fake-auth-token", nil
		default:
			return nil, &APIError{Code: -1, Message: "unexpected", Data: method}
		}
	})
	defer ts.Close()

	cfg := config.DefaultConfig()
	cfg.Zabbix.FrontURL = ts.URL
	cfg.Zabbix.APIUser = "Admin"
	cfg.Zabbix.APIPassword = "zabbix"

	c, err := NewClient(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if c.apiVersion != "7.0.0" {
		t.Errorf("apiVersion = %q, want 7.0.0", c.apiVersion)
	}
	if c.authToken != "fake-auth-token" {
		t.Errorf("authToken = %q, want fake-auth-token", c.authToken)
	}
	if len(gotMethods) != 2 || gotMethods[0] != "apiinfo.version" || gotMethods[1] != "user.login" {
		t.Errorf("methods = %v, want [apiinfo.version, user.login]", gotMethods)
	}
}

func TestNewClient_AuthFailure(t *testing.T) {
	ts := newTestServer(t, func(method string, _ json.RawMessage) (interface{}, *APIError) {
		switch method {
		case "apiinfo.version":
			return "7.0.0", nil
		case "user.login":
			return nil, &APIError{Code: -32602, Message: "Login failed", Data: "bad creds"}
		default:
			return nil, nil
		}
	})
	defer ts.Close()

	cfg := config.DefaultConfig()
	cfg.Zabbix.FrontURL = ts.URL

	_, err := NewClient(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected error for bad credentials")
	}
}

func TestGetHostByIDCtx(t *testing.T) {
	ts := newTestServer(t, func(method string, _ json.RawMessage) (interface{}, *APIError) {
		if method == "host.get" {
			return []map[string]interface{}{
				{
					"hostid": "10084",
					"host":   "webserver01",
					"name":   "Web Server 01",
					"status": "0",
				},
			}, nil
		}
		return nil, &APIError{Code: -1, Message: "unexpected", Data: method}
	})
	defer ts.Close()

	c := newTestClient(t, ts)

	host, err := c.GetHostByIDCtx(context.Background(), "10084")
	if err != nil {
		t.Fatalf("GetHostByIDCtx: %v", err)
	}
	if host.HostID != "10084" {
		t.Errorf("hostid = %q, want 10084", host.HostID)
	}
	if host.Name != "Web Server 01" {
		t.Errorf("name = %q, want Web Server 01", host.Name)
	}
}

func TestGetHostByIDCtx_NotFound(t *testing.T) {
	ts := newTestServer(t, func(method string, _ json.RawMessage) (interface{}, *APIError) {
		return []interface{}{}, nil
	})
	defer ts.Close()

	c := newTestClient(t, ts)

	_, err := c.GetHostByIDCtx(context.Background(), "99999")
	if err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestGetHostByNameCtx(t *testing.T) {
	ts := newTestServer(t, func(method string, _ json.RawMessage) (interface{}, *APIError) {
		if method == "host.get" {
			return []map[string]interface{}{
				{"hostid": "10084", "host": "webserver01", "name": "Web Server 01"},
			}, nil
		}
		return nil, nil
	})
	defer ts.Close()

	c := newTestClient(t, ts)

	host, err := c.GetHostByNameCtx(context.Background(), "webserver01")
	if err != nil {
		t.Fatalf("GetHostByNameCtx: %v", err)
	}
	if host.Host != "webserver01" {
		t.Errorf("host = %q, want webserver01", host.Host)
	}
}

func TestGetHostItemsCtx(t *testing.T) {
	ts := newTestServer(t, func(method string, _ json.RawMessage) (interface{}, *APIError) {
		if method == "item.get" {
			return []map[string]interface{}{
				{
					"itemid":     "28001",
					"hostid":     "10084",
					"name":       "OS packages",
					"key_":       "system.sw.packages",
					"lastvalue":  "nginx 1.18.0\ncurl 7.68.0",
					"value_type": "4",
					"state":      "0",
				},
			}, nil
		}
		return nil, nil
	})
	defer ts.Close()

	c := newTestClient(t, ts)

	items, err := c.GetHostItemsCtx(context.Background(), "10084", "system.sw.packages")
	if err != nil {
		t.Fatalf("GetHostItemsCtx: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if items[0].Key != "system.sw.packages" {
		t.Errorf("key = %q, want system.sw.packages", items[0].Key)
	}
}

func TestGetItemValueCtx(t *testing.T) {
	ts := newTestServer(t, func(method string, params json.RawMessage) (interface{}, *APIError) {
		switch method {
		case "host.get":
			return []map[string]interface{}{
				{"hostid": "10200"},
			}, nil
		case "item.get":
			return []map[string]interface{}{
				{"itemid": "30001", "hostid": "10200", "key_": "vulners.hosts_lld", "lastvalue": `{"data":[]}`},
			}, nil
		}
		return nil, nil
	})
	defer ts.Close()

	c := newTestClient(t, ts)

	val, err := c.GetItemValueCtx(context.Background(), "vulners.hosts", "vulners.hosts_lld")
	if err != nil {
		t.Fatalf("GetItemValueCtx: %v", err)
	}
	if val != `{"data":[]}` {
		t.Errorf("value = %q, want {\"data\":[]}", val)
	}
}

func TestGetHostsWithTemplateCtx(t *testing.T) {
	ts := newTestServer(t, func(method string, _ json.RawMessage) (interface{}, *APIError) {
		switch method {
		case "template.get":
			return []map[string]interface{}{
				{"templateid": "10001", "host": "tmpl.vulners.os-report", "name": "OS Report"},
			}, nil
		case "host.get":
			return []map[string]interface{}{
				{"hostid": "10084", "host": "web01", "name": "Web 01", "status": "0"},
				{"hostid": "10085", "host": "web02", "name": "Web 02", "status": "0"},
			}, nil
		}
		return nil, nil
	})
	defer ts.Close()

	c := newTestClient(t, ts)

	hosts, err := c.GetHostsWithTemplateCtx(context.Background(), "tmpl.vulners.os-report")
	if err != nil {
		t.Fatalf("GetHostsWithTemplateCtx: %v", err)
	}
	if len(hosts) != 2 {
		t.Errorf("len(hosts) = %d, want 2", len(hosts))
	}
}

func TestGetHostsWithTemplateCtx_TemplateNotFound(t *testing.T) {
	ts := newTestServer(t, func(method string, _ json.RawMessage) (interface{}, *APIError) {
		return []interface{}{}, nil
	})
	defer ts.Close()

	c := newTestClient(t, ts)

	_, err := c.GetHostsWithTemplateCtx(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing template")
	}
}

func TestClose_LogsOut(t *testing.T) {
	var loggedOut bool
	ts := newTestServer(t, func(method string, _ json.RawMessage) (interface{}, *APIError) {
		if method == "user.logout" {
			loggedOut = true
			return true, nil
		}
		return nil, nil
	})
	defer ts.Close()

	c := newTestClient(t, ts)

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !loggedOut {
		t.Error("expected user.logout to be called")
	}
	if c.authToken != "" {
		t.Error("authToken should be cleared after Close")
	}
}

func TestClose_NoAuthToken(t *testing.T) {
	c := &Client{}
	if err := c.Close(); err != nil {
		t.Fatalf("Close with no token: %v", err)
	}
}

func TestCreateHostCtx(t *testing.T) {
	ts := newTestServer(t, func(method string, _ json.RawMessage) (interface{}, *APIError) {
		if method == "host.create" {
			return map[string]interface{}{
				"hostids": []interface{}{"10300"},
			}, nil
		}
		return nil, nil
	})
	defer ts.Close()

	c := newTestClient(t, ts)

	host := &Host{Host: "test-host", Name: "Test Host"}
	hostID, err := c.CreateHostCtx(context.Background(), host, []string{"1"}, []string{"100"})
	if err != nil {
		t.Fatalf("CreateHostCtx: %v", err)
	}
	if hostID != "10300" {
		t.Errorf("hostID = %q, want 10300", hostID)
	}
}

func TestAPIError_Error(t *testing.T) {
	e := &APIError{Code: -32602, Message: "Invalid params", Data: "bad field"}
	got := e.Error()
	want := "Invalid params: bad field"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
