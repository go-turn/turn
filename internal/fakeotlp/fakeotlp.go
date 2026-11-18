// Package fakeotlp is an in-process OTLP collector for tests. It serves OTLP/HTTP
// (protobuf, /v1/traces, /v1/metrics, /v1/logs) and OTLP/gRPC on loopback,
// decodes what it receives, and keeps every raw request body so a test can
// assert that a string never reached the collector.
package fakeotlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	respb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// Collector is a running collector.
type Collector struct {
	// URL is the OTLP/HTTP base ("http://127.0.0.1:port"); GRPCAddr is host:port.
	URL, GRPCAddr string

	mu        sync.Mutex
	raw       [][]byte
	auth      []string // Authorization of every request
	resources []*respb.Resource
	spans     []*tracepb.Span
	metrics   []*metricspb.Metric
	logs      []*logspb.LogRecord
}

// New starts a collector and stops it at the end of the test.
func New(t testing.TB) *Collector {
	t.Helper()
	c := &Collector{}
	hs := httptest.NewServer(http.HandlerFunc(c.serveHTTP))
	t.Cleanup(hs.Close)
	c.URL = hs.URL
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	coltrace.RegisterTraceServiceServer(gs, traceSvc{c: c})
	colmetrics.RegisterMetricsServiceServer(gs, metricSvc{c: c})
	collogs.RegisterLogsServiceServer(gs, logSvc{c: c})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	c.GRPCAddr = lis.Addr().String()
	return c
}

func (c *Collector) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body := r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body = zr
	}
	b, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.auth = append(c.auth, r.Header.Get("Authorization"))
	c.mu.Unlock()
	var msg proto.Message
	switch r.URL.Path {
	case "/v1/traces":
		msg = &coltrace.ExportTraceServiceRequest{}
	case "/v1/metrics":
		msg = &colmetrics.ExportMetricsServiceRequest{}
	case "/v1/logs":
		msg = &collogs.ExportLogsServiceRequest{}
	default:
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Content-Type") != "application/x-protobuf" || proto.Unmarshal(b, msg) != nil {
		http.Error(w, "want application/x-protobuf", http.StatusBadRequest)
		return
	}
	c.keep(b, msg)
	w.Header().Set("Content-Type", "application/x-protobuf")
}

func (c *Collector) keep(b []byte, msg proto.Message) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.raw = append(c.raw, b)
	switch m := msg.(type) {
	case *coltrace.ExportTraceServiceRequest:
		for _, rs := range m.ResourceSpans {
			c.resources = append(c.resources, rs.Resource)
			for _, ss := range rs.ScopeSpans {
				c.spans = append(c.spans, ss.Spans...)
			}
		}
	case *colmetrics.ExportMetricsServiceRequest:
		for _, rm := range m.ResourceMetrics {
			c.resources = append(c.resources, rm.Resource)
			for _, sm := range rm.ScopeMetrics {
				c.metrics = append(c.metrics, sm.Metrics...)
			}
		}
	case *collogs.ExportLogsServiceRequest:
		for _, rl := range m.ResourceLogs {
			c.resources = append(c.resources, rl.Resource)
			for _, sl := range rl.ScopeLogs {
				c.logs = append(c.logs, sl.LogRecords...)
			}
		}
	}
}

func (c *Collector) grpcAuth(ctx context.Context) {
	md, _ := metadata.FromIncomingContext(ctx)
	c.mu.Lock()
	c.auth = append(c.auth, strings.Join(md.Get("authorization"), ","))
	c.mu.Unlock()
}

func (c *Collector) exportAny(ctx context.Context, m proto.Message) {
	c.grpcAuth(ctx)
	b, _ := proto.Marshal(m)
	c.keep(b, m)
}

// The three OTLP gRPC services each have an Export with its own request type.
type traceSvc struct {
	coltrace.UnimplementedTraceServiceServer
	c *Collector
}
type metricSvc struct {
	colmetrics.UnimplementedMetricsServiceServer
	c *Collector
}
type logSvc struct {
	collogs.UnimplementedLogsServiceServer
	c *Collector
}

func (s traceSvc) Export(ctx context.Context, r *coltrace.ExportTraceServiceRequest) (*coltrace.ExportTraceServiceResponse, error) {
	s.c.exportAny(ctx, r)
	return &coltrace.ExportTraceServiceResponse{}, nil
}
func (s metricSvc) Export(ctx context.Context, r *colmetrics.ExportMetricsServiceRequest) (*colmetrics.ExportMetricsServiceResponse, error) {
	s.c.exportAny(ctx, r)
	return &colmetrics.ExportMetricsServiceResponse{}, nil
}
func (s logSvc) Export(ctx context.Context, r *collogs.ExportLogsServiceRequest) (*collogs.ExportLogsServiceResponse, error) {
	s.c.exportAny(ctx, r)
	return &collogs.ExportLogsServiceResponse{}, nil
}

// Wait polls until cond holds or 10 s pass.
func (c *Collector) Wait(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("collector: timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Raw is every request body received, decompressed, concatenated.
func (c *Collector) Raw() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Join(c.raw, nil)
}

// Auth is the Authorization of every request received.
func (c *Collector) Auth() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.auth...)
}

// Resources, Spans, Metrics and Logs return what was decoded so far.
func (c *Collector) Resources() []*respb.Resource {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*respb.Resource(nil), c.resources...)
}
func (c *Collector) Spans() []*tracepb.Span {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*tracepb.Span(nil), c.spans...)
}
func (c *Collector) Metrics() []*metricspb.Metric {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*metricspb.Metric(nil), c.metrics...)
}
func (c *Collector) Logs() []*logspb.LogRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*logspb.LogRecord(nil), c.logs...)
}

// Attr returns the string value of key in kvs.
func Attr(kvs []*commonpb.KeyValue, key string) (string, bool) {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.GetValue().GetStringValue(), true
		}
	}
	return "", false
}

// HasMetric reports whether a metric named name was received.
func (c *Collector) HasMetric(name string) bool {
	for _, m := range c.Metrics() {
		if m.Name == name {
			return true
		}
	}
	return false
}
