package fixer

// FixOptions configures a fix operation
type FixOptions struct {
	BulletinID string // Bulletin ID to fix (optional)
	HostID     string // Specific host ID to fix (optional)
	HostName   string // Host technical name to fix (optional, resolved to HostID)
	DryRun     bool   // Don't execute, just show plan
	UseSSH     bool   // Use SSH instead of Zabbix agent
	SSHUser    string // SSH user for remote execution (default: root)
}

// FixPlan describes the fix actions to take
type FixPlan struct {
	Hosts    []HostFixPlan
	Packages []string
}

// HostFixPlan describes fix actions for a single host
type HostFixPlan struct {
	HostID    string
	Name      string
	IP        string
	AgentPort string // Zabbix agent port (default "10050")
	Packages  []string
	Command   string
}

// FixResults contains the results of a fix operation
type FixResults struct {
	Successful int
	Failed     int
	Hosts      []HostFixResult
}

// HostFixResult contains the result of fixing a single host
type HostFixResult struct {
	HostID  string
	Name    string
	Success bool
	Output  string
	Error   string
}
