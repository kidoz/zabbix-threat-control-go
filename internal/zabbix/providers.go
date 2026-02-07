package zabbix

import "github.com/google/wire"

// ProviderSet provides Zabbix client and sender for Wire injection.
var ProviderSet = wire.NewSet(NewClient, NewSender)
