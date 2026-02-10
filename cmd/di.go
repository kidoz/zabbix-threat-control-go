package cmd

import (
	"log/slog"

	"go.uber.org/fx"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/fixer"
	"github.com/kidoz/zabbix-threat-control-go/internal/scanner"
	"github.com/kidoz/zabbix-threat-control-go/internal/zabbix"
)

func initScanner(cfg *config.Config, log *slog.Logger) (*scanner.Scanner, error) {
	var s *scanner.Scanner
	app := fx.New(
		fx.NopLogger,
		fx.Supply(cfg, log),
		scanner.Module,
		fx.Populate(&s),
	)
	if err := app.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

func initFixer(cfg *config.Config, log *slog.Logger) (*fixer.Fixer, error) {
	var f *fixer.Fixer
	app := fx.New(
		fx.NopLogger,
		fx.Supply(cfg, log),
		fixer.Module,
		fx.Populate(&f),
	)
	if err := app.Err(); err != nil {
		return nil, err
	}
	return f, nil
}

func initZabbixClient(cfg *config.Config, log *slog.Logger) (*zabbix.Client, error) {
	var c *zabbix.Client
	app := fx.New(
		fx.NopLogger,
		fx.Supply(cfg, log),
		zabbix.Module,
		fx.Populate(&c),
	)
	if err := app.Err(); err != nil {
		return nil, err
	}
	return c, nil
}
