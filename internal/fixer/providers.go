package fixer

import (
	"github.com/google/wire"
	"go.uber.org/zap"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/zabbix"
)

// ProviderSet provides all fixer dependencies for Wire injection.
var ProviderSet = wire.NewSet(
	ProvideFixer,
	NewExecutor,
	zabbix.ProviderSet,
)

// ProvideFixer assembles a Fixer from its Wire-injected dependencies.
func ProvideFixer(
	cfg *config.Config,
	log *zap.Logger,
	zabbixClient *zabbix.Client,
	executor *Executor,
) *Fixer {
	return &Fixer{
		cfg:          cfg,
		log:          log,
		zabbixClient: zabbixClient,
		executor:     executor,
	}
}
