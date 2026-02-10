package fixer

import (
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/zabbix"
)

// Module provides all fixer dependencies for fx injection.
var Module = fx.Module("fixer",
	fx.Provide(ProvideFixer, NewExecutor),
	zabbix.Module,
)

// ProvideFixer assembles a Fixer from its injected dependencies.
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
