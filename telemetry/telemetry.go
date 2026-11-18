package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

const scope = "github.com/go-turn/turn/telemetry"

// Telemetry is the running pipeline: a tracer, the instruments and the log
// handler. A disabled one (Setup with no endpoint) is a no-op everywhere.
type Telemetry struct {
	cfg        Config
	tracer     trace.Tracer
	tp         trace.TracerProvider
	mp         metric.MeterProvider
	propagator propagation.TextMapPropagator
	metrics    *Metrics
	logs       slog.Handler // nil when disabled
	shutdown   []func(context.Context) error
}

// Enabled reports whether telemetry is exporting.
func (t *Telemetry) Enabled() bool { return t.cfg.Enabled() }

// Metrics returns the instruments (inert when disabled).
func (t *Telemetry) Metrics() *Metrics { return t.metrics }

// TracerProvider and MeterProvider are for the gRPC instrumentation.
func (t *Telemetry) TracerProvider() trace.TracerProvider { return t.tp }
func (t *Telemetry) MeterProvider() metric.MeterProvider  { return t.mp }

// Propagator is the propagator the gRPC server instrumentation extracts a
// caller's context with: W3C Trace Context when the configuration trusts the
// caller, otherwise an empty one, so the RPC starts its own trace.
func (t *Telemetry) Propagator() propagation.TextMapPropagator {
	if t.cfg.TrustClientContext {
		return propagation.TraceContext{}
	}
	return propagation.NewCompositeTextMapPropagator()
}

// ignoredEnv lists the OTLP environment variables that could carry a secret.
// The SDK reads them on its own; Setup overrides the headers with an explicit
// (possibly empty) set so none of them is ever sent, and reports them.
var ignoredEnv = []string{
	"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
	"OTEL_EXPORTER_OTLP_METRICS_HEADERS", "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
}

// Setup builds the pipeline for cfg. warn receives one line per ignored
// environment variable. With no endpoint it returns a disabled Telemetry.
func Setup(ctx context.Context, cfg Config, warn func(string)) (*Telemetry, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "turnd"
	}
	if cfg.MetricInterval <= 0 {
		cfg.MetricInterval = time.Minute
	}
	t := &Telemetry{cfg: cfg, tp: tracenoop.NewTracerProvider(), mp: metricnoop.NewMeterProvider()}
	t.tracer = t.tp.Tracer(scope)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled() {
		t.metrics = newMetrics(t.mp.Meter(scope), t.tracer)
		return t, nil
	}
	if warn != nil {
		for _, k := range ignoredEnv {
			if os.Getenv(k) != "" {
				warn(k + " is set and ignored: the collector token is read from --otel-token-file only")
			}
		}
	}
	headers := map[string]string{}
	if cfg.Token != "" {
		headers["Authorization"] = "Bearer " + cfg.Token
	}
	var id [8]byte
	_, _ = rand.Read(id[:])
	res := resource.NewSchemaless(
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("service.version", cfg.Version),
		attribute.String("service.instance.id", hex.EncodeToString(id[:])),
	)

	var (
		spanExp sdktrace.SpanExporter
		metExp  sdkmetric.Exporter
		logExp  sdklog.Exporter
		err     error
	)
	switch cfg.Protocol {
	case "grpc":
		topts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(cfg.Endpoint), otlptracegrpc.WithHeaders(headers)}
		mopts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(cfg.Endpoint), otlpmetricgrpc.WithHeaders(headers)}
		lopts := []otlploggrpc.Option{otlploggrpc.WithEndpoint(cfg.Endpoint), otlploggrpc.WithHeaders(headers)}
		if cfg.Insecure {
			topts = append(topts, otlptracegrpc.WithInsecure())
			mopts = append(mopts, otlpmetricgrpc.WithInsecure())
			lopts = append(lopts, otlploggrpc.WithInsecure())
		}
		if spanExp, err = otlptracegrpc.New(ctx, topts...); err == nil {
			if metExp, err = otlpmetricgrpc.New(ctx, mopts...); err == nil {
				logExp, err = otlploggrpc.New(ctx, lopts...)
			}
		}
	default:
		base := strings.TrimRight(cfg.Endpoint, "/")
		if spanExp, err = otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(base+"/v1/traces"), otlptracehttp.WithHeaders(headers)); err == nil {
			if metExp, err = otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(base+"/v1/metrics"), otlpmetrichttp.WithHeaders(headers)); err == nil {
				logExp, err = otlploghttp.New(ctx, otlploghttp.WithEndpointURL(base+"/v1/logs"), otlploghttp.WithHeaders(headers))
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("telemetry: exporter: %w", err)
	}

	var bopts []sdktrace.BatchSpanProcessorOption
	var lopts []sdklog.BatchProcessorOption
	if cfg.BatchInterval > 0 {
		bopts = append(bopts, sdktrace.WithBatchTimeout(cfg.BatchInterval))
		lopts = append(lopts, sdklog.WithExportInterval(cfg.BatchInterval))
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(scrubExporter{spanExp}, bopts...),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
	)
	deny := attribute.NewDenyKeysFilter(deniedKeys...)
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metExp, sdkmetric.WithInterval(cfg.MetricInterval))),
		sdkmetric.WithResource(res),
		sdkmetric.WithView(sdkmetric.NewView(sdkmetric.Instrument{Name: "*"}, sdkmetric.Stream{AttributeFilter: deny})),
	)
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp, lopts...)),
		sdklog.WithResource(res),
	)
	t.tp, t.mp = tp, mp
	t.tracer = tp.Tracer(scope)
	t.propagator = propagation.TraceContext{}
	t.metrics = newMetrics(mp.Meter(scope), t.tracer)
	t.logs = redactHandler{otelslog.NewHandler(scope, otelslog.WithLoggerProvider(lp))}
	t.shutdown = []func(context.Context) error{tp.Shutdown, mp.Shutdown, lp.Shutdown}
	return t, nil
}

// Shutdown flushes and stops every signal.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	var errs []error
	for _, f := range t.shutdown {
		if err := f(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Logger builds turnd's logger: JSON on w (journald-friendly), each record
// carrying trace_id and span_id when a span is active in its context, and, when
// telemetry is on, the same records exported over OTLP through the slog bridge
// after redaction.
func (t *Telemetry) Logger(w io.Writer, level slog.Level) *slog.Logger {
	var h slog.Handler = traceHandler{slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})}
	if t.logs != nil {
		h = fanout{h, levelHandler{t.logs, level}}
	}
	return slog.New(h)
}

type traceHandler struct{ slog.Handler }

func (h traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return h.Handler.Handle(ctx, r)
}
func (h traceHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return traceHandler{h.Handler.WithAttrs(as)}
}
func (h traceHandler) WithGroup(n string) slog.Handler { return traceHandler{h.Handler.WithGroup(n)} }

// levelHandler applies the logger's level to a handler that has none of its own.
type levelHandler struct {
	slog.Handler
	min slog.Level
}

func (h levelHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= h.min && h.Handler.Enabled(ctx, l)
}
func (h levelHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return levelHandler{h.Handler.WithAttrs(as), h.min}
}
func (h levelHandler) WithGroup(n string) slog.Handler {
	return levelHandler{h.Handler.WithGroup(n), h.min}
}

// fanout sends a record to both handlers.
type fanout struct{ a, b slog.Handler }

func (f fanout) Enabled(ctx context.Context, l slog.Level) bool {
	return f.a.Enabled(ctx, l) || f.b.Enabled(ctx, l)
}
func (f fanout) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if f.a.Enabled(ctx, r.Level) {
		err = f.a.Handle(ctx, r.Clone())
	}
	if f.b.Enabled(ctx, r.Level) {
		if e := f.b.Handle(ctx, r.Clone()); err == nil {
			err = e
		}
	}
	return err
}
func (f fanout) WithAttrs(as []slog.Attr) slog.Handler {
	return fanout{f.a.WithAttrs(as), f.b.WithAttrs(as)}
}
func (f fanout) WithGroup(n string) slog.Handler { return fanout{f.a.WithGroup(n), f.b.WithGroup(n)} }
