package zabbix

// Host represents a Zabbix host
type Host struct {
	HostID     string          `json:"hostid"`
	Host       string          `json:"host"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	Interfaces []HostInterface `json:"interfaces,omitempty"`
	Groups     []HostGroup     `json:"groups,omitempty"`
	Templates  []Template      `json:"parentTemplates,omitempty"`
}

// HostInterface represents a Zabbix host interface
type HostInterface struct {
	InterfaceID string `json:"interfaceid"`
	IP          string `json:"ip"`
	DNS         string `json:"dns"`
	Port        string `json:"port"`
	Type        string `json:"type"`
	Main        string `json:"main"`
	UseIP       string `json:"useip"`
}

// HostGroup represents a Zabbix host group
type HostGroup struct {
	GroupID string `json:"groupid"`
	Name    string `json:"name"`
}

// Template represents a Zabbix template
type Template struct {
	TemplateID string `json:"templateid"`
	Host       string `json:"host"`
	Name       string `json:"name"`
}

// Item represents a Zabbix item
type Item struct {
	ItemID    string `json:"itemid"`
	HostID    string `json:"hostid"`
	Name      string `json:"name"`
	Key       string `json:"key_"`
	Value     string `json:"lastvalue"`
	ValueType string `json:"value_type"`
	State     string `json:"state"`
}

// Trigger represents a Zabbix trigger
type Trigger struct {
	TriggerID   string `json:"triggerid"`
	Description string `json:"description"`
	Expression  string `json:"expression"`
	Priority    string `json:"priority"`
	Status      string `json:"status"`
	Value       string `json:"value"`
}

// Event represents a Zabbix event
type Event struct {
	EventID      string `json:"eventid"`
	ObjectID     string `json:"objectid"`
	Clock        string `json:"clock"`
	Name         string `json:"name"`
	Severity     string `json:"severity"`
	Acknowledged string `json:"acknowledged"`
}

// Dashboard represents a Zabbix dashboard
type Dashboard struct {
	DashboardID string          `json:"dashboardid"`
	Name        string          `json:"name"`
	Pages       []DashboardPage `json:"pages,omitempty"`
}

// DashboardPage represents a page in a Zabbix dashboard
type DashboardPage struct {
	Widgets []DashboardWidget `json:"widgets,omitempty"`
}

// DashboardWidget represents a widget on a dashboard page
type DashboardWidget struct {
	Type   string                 `json:"type"`
	Name   string                 `json:"name"`
	X      int                    `json:"x"`
	Y      int                    `json:"y"`
	Width  int                    `json:"width"`
	Height int                    `json:"height"`
	Fields []DashboardWidgetField `json:"fields,omitempty"`
}

// DashboardWidgetField represents a field in a dashboard widget
type DashboardWidgetField struct {
	Type  int    `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Action represents a Zabbix action
type Action struct {
	ActionID   string `json:"actionid"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	EventsMode string `json:"eventsource"`
}

// APIResponse represents a generic Zabbix API response
type APIResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result"`
	Error   *APIError   `json:"error,omitempty"`
	ID      int         `json:"id"`
}

// APIError represents a Zabbix API error
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

func (e *APIError) Error() string {
	return e.Message + ": " + e.Data
}

// LLDData represents Low-Level Discovery data for Zabbix
type LLDData struct {
	Data []map[string]interface{} `json:"data"`
}

// HostLLDEntry represents a host entry for LLD
type HostLLDEntry struct {
	HostID  string  `json:"{#H.ID}"`
	Host    string  `json:"{#H.HOST}"`
	VisName string  `json:"{#H.VNAME}"`
	Score   float64 `json:"{#H.SCORE}"`
}

// PackageLLDEntry represents a package entry for LLD
type PackageLLDEntry struct {
	HostID  string  `json:"{#P.HOSTID}"`
	Package string  `json:"{#P.NAME}"`
	Version string  `json:"{#P.VERSION}"`
	Score   float64 `json:"{#P.SCORE}"`
	Fix     string  `json:"{#P.FIX}"`
}

// BulletinLLDEntry represents a bulletin entry for LLD
type BulletinLLDEntry struct {
	ID       string  `json:"{#B.ID}"`
	Type     string  `json:"{#B.TYPE}"`
	Score    float64 `json:"{#B.SCORE}"`
	Affected int     `json:"{#B.AFFECTED}"`
}
