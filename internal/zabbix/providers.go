package zabbix

import "go.uber.org/fx"

// Module provides Zabbix client and sender for fx injection.
var Module = fx.Module("zabbix",
	fx.Provide(NewClient, NewSender),
)
