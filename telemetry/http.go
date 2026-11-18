package telemetry

import (
	"bufio"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// HTTP wraps h in a server span and the request-duration histogram, following
// the HTTP semantic conventions: the span is named "{method} {http.route}", a 5xx
// sets the status to Error and a 4xx leaves it unset.
//
// The URL's query is never recorded (the callback's holds the authorization
// code and the state) and neither is the client address, the user agent or any
// header. url.path is recorded only for a route that exists, so a scanner's
// path cannot become an attribute. Requests whose path is in skip (the gRPC
// WebSocket, whose RPCs the gRPC instrumentation traces) pass through.
//
// A caller's traceparent is continued only with Config.TrustClientContext;
// otherwise the trace restarts here (W3C Trace Context 3.4, 7.2).
func (t *Telemetry) HTTP(h http.Handler, skip ...string) http.Handler {
	if !t.Enabled() {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range skip {
			if r.URL.Path == p {
				h.ServeHTTP(w, r)
				return
			}
		}
		ctx := r.Context()
		if t.cfg.TrustClientContext {
			ctx = propagation.TraceContext{}.Extract(ctx, propagation.HeaderCarrier(r.Header))
		} else {
			ctx = trace.ContextWithSpanContext(ctx, trace.SpanContext{})
		}
		method := r.Method
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete,
			http.MethodPatch, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		default:
			method = "_OTHER"
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		start := time.Now()
		ctx, span := t.tracer.Start(ctx, "HTTP", trace.WithSpanKind(trace.SpanKindServer), trace.WithTimestamp(start),
			trace.WithAttributes(attribute.String("http.request.method", method), attribute.String("url.scheme", scheme)))
		rec := &statusRecorder{ResponseWriter: w}
		r2 := r.WithContext(ctx)
		h.ServeHTTP(rec, r2) // the mux records the matched pattern on r2
		status := rec.code
		if status == 0 {
			status = http.StatusOK
		}
		route := routeOf(r2.Pattern)
		attrs := []attribute.KeyValue{attribute.String("http.request.method", method), attribute.Int("http.response.status_code", status)}
		name := method
		if method == "_OTHER" {
			name = "HTTP"
		}
		if route != "" {
			attrs = append(attrs, attribute.String("http.route", route))
			span.SetAttributes(attribute.String("url.path", route), attribute.String("http.route", route))
			name += " " + route
		}
		span.SetName(name)
		span.SetAttributes(attribute.Int("http.response.status_code", status))
		if status >= 500 {
			attrs = append(attrs, attribute.String("error.type", strconv.Itoa(status)))
			span.SetAttributes(attribute.String("error.type", strconv.Itoa(status)))
			span.SetStatus(codes.Error, "")
		}
		span.End()
		t.metrics.httpDur.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	})
}

// routeOf is the path of a ServeMux pattern ("GET /login" is "/login").
func routeOf(pattern string) string {
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		pattern = pattern[i+1:]
	}
	return pattern
}

// statusRecorder keeps the status code and passes through what a handler may
// need from the connection (Hijack for the WebSocket, Flush).
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) {
	if s.code == 0 {
		s.code = c
	}
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(s.ResponseWriter).Hijack()
}

func (s *statusRecorder) Flush() { _ = http.NewResponseController(s.ResponseWriter).Flush() }
