//go:build wireinject

package cmd

import (
	"github.com/google/wire"
	"go.uber.org/zap"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/fixer"
	"github.com/kidoz/zabbix-threat-control-go/internal/scanner"
	"github.com/kidoz/zabbix-threat-control-go/internal/zabbix"
)

func initScanner(cfg *config.Config, log *zap.Logger) (*scanner.Scanner, error) {
	wire.Build(scanner.ProviderSet)
	return nil, nil
}

func initFixer(cfg *config.Config, log *zap.Logger) (*fixer.Fixer, error) {
	wire.Build(fixer.ProviderSet)
	return nil, nil
}

func initZabbixClient(cfg *config.Config, log *zap.Logger) (*zabbix.Client, error) {
	wire.Build(zabbix.ProviderSet)
	return nil, nil
}
