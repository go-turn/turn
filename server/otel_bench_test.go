package server_test

import (
	"context"
	"os"

	"github.com/go-turn/turn/server"
	"github.com/go-turn/turn/telemetry"
	"go.opentelemetry.io/otel"
)

// With TURN_BENCH_OTEL=1 the server benchmarks run with the real telemetry
// pipeline on: every trace sampled, spans and metrics queued for an exporter
// whose collector is unreachable (the export is asynchronous, so the benchmark
// pays for recording, not for the network). Without it they run as before.
func init() {
	if os.Getenv("TURN_BENCH_OTEL") == "" {
		return
	}
	// the unreachable collector would print an export error into the results
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {}))
	cfg := telemetry.DefaultConfig()
	cfg.Endpoint, cfg.Insecure = "http://127.0.0.1:1", true
	tel, err := telemetry.Setup(context.Background(), cfg, nil)
	if err != nil {
		panic(err)
	}
	server.SetBenchObserver(tel.Metrics().ServerObserver())
}
