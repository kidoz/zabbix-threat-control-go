package telemetry

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
)

func TestInit_Disabled(t *testing.T) {
	cfg := &config.TelemetryConfig{Enabled: false}

	shutdown, err := Init(context.Background(), cfg, false)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Should have set a noop provider
	tp := otel.GetTracerProvider()
	if _, ok := tp.(noop.TracerProvider); !ok {
		t.Errorf("expected noop.TracerProvider, got %T", tp)
	}

	// Shutdown should succeed
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

func TestInit_EnabledNoEndpointNotVerbose(t *testing.T) {
	cfg := &config.TelemetryConfig{Enabled: true}

	shutdown, err := Init(context.Background(), cfg, false)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Enabled but no endpoint and not verbose → noop
	tp := otel.GetTracerProvider()
	if _, ok := tp.(noop.TracerProvider); !ok {
		t.Errorf("expected noop.TracerProvider for no-endpoint/no-verbose, got %T", tp)
	}

	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

func TestInit_EnabledVerbose(t *testing.T) {
	cfg := &config.TelemetryConfig{Enabled: true}

	shutdown, err := Init(context.Background(), cfg, true)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	// Should have installed an SDK provider (not noop)
	tp := otel.GetTracerProvider()
	if _, ok := tp.(noop.TracerProvider); ok {
		t.Error("expected real TracerProvider with verbose, got noop")
	}
}

func TestTracer_ReturnsTracer(t *testing.T) {
	tracer := Tracer()
	if tracer == nil {
		t.Fatal("Tracer() returned nil")
	}
}
