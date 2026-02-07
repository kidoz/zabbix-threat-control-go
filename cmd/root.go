package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
	"github.com/kidoz/zabbix-threat-control-go/internal/telemetry"
)

var (
	cfgFile      string
	verbose      bool
	cfg          *config.Config
	log          *zap.Logger
	otelShutdown func(context.Context) error
)

var rootCmd = &cobra.Command{
	Use:   "ztc",
	Short: "Zabbix Threat Control - vulnerability assessment for Zabbix",
	Long: `Zabbix Threat Control (ZTC) transforms Zabbix monitoring
into a vulnerability assessment system using the Vulners API.

It scans hosts monitored by Zabbix for security vulnerabilities
in installed packages and reports them back to Zabbix for
centralized monitoring and alerting.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip config loading for commands that handle their own config
		if cmd.Name() == "version" || cmd.Name() == "migrate-config" {
			return nil
		}

		// Initialize logger
		log = newLogger(verbose)

		// Load configuration
		var err error
		cfg, err = config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Initialize OpenTelemetry
		otelShutdown, err = telemetry.Init(context.Background(), &cfg.Telemetry, verbose)
		if err != nil {
			return fmt.Errorf("failed to init telemetry: %w", err)
		}

		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		if log != nil {
			_ = log.Sync()
		}
		if otelShutdown != nil {
			return otelShutdown(context.Background())
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", config.FindConfigPath(), "config file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
}

func GetConfig() *config.Config {
	return cfg
}

func GetLogger() *zap.Logger {
	return log
}

func newLogger(verbose bool) *zap.Logger {
	level := zap.InfoLevel
	if verbose {
		level = zap.DebugLevel
	}
	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Encoding:         "console",
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "T",
			LevelKey:       "L",
			MessageKey:     "M",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.CapitalLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
		},
	}
	logger, _ := cfg.Build()
	return logger
}
