// Package telemetry is turnd's OpenTelemetry: traces, metrics and logs pushed
// over OTLP, with the official Go SDK. It is off, and costs nothing, until an
// endpoint is configured.
//
// References opened for this package (2026-11-18):
//   - OTLP specification, https://opentelemetry.io/docs/specs/otlp/ : OTLP/gRPC
//     on 4317, OTLP/HTTP on 4318 with /v1/traces, /v1/metrics and /v1/logs and
//     the application/x-protobuf content type.
//   - W3C Trace Context, https://www.w3.org/TR/trace-context/ : section 3.4
//     (restarting a trace at the front gate of a secure network), 6.1 (privacy)
//     and 7.2 (denial of monitoring by a public caller).
//   - OpenTelemetry semantic conventions: HTTP spans (a server span is named
//     "{method} {http.route}", a 4xx leaves the status unset, a 5xx sets Error),
//     gRPC (rpc.system.name grpc, rpc.method, rpc.status_code) and the network
//     attributes (network.transport, network.type).
//
// The two things a collector must never learn from turnd are credentials and
// people: no token, code, cookie, password, room ID or TURN username, and no
// client or peer address, ever reaches a span, a metric or a log record. See
// the scrubbing in scrub.go, which applies to what the SDK instrumentation adds
// on its own as well.
package telemetry

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Config is the telemetry configuration. The zero value (no Endpoint) is off.
type Config struct {
	// Endpoint is the collector: https://host:4318 for Protocol "http" (the
	// signal paths /v1/traces, /v1/metrics and /v1/logs are appended), host:4317
	// for "grpc". Empty turns telemetry off.
	Endpoint string
	// Protocol is "http" (default) or "grpc".
	Protocol string
	// Token is the collector's bearer token, already read from its file. It is
	// sent as "Authorization: Bearer <token>" and nowhere else.
	Token string
	// Insecure allows http:// (or plaintext gRPC) to the collector.
	Insecure bool
	// SampleRatio is the fraction of traces kept, 0..1 (default 1: DefaultConfig).
	SampleRatio float64
	// ServiceName is service.name (default "turnd").
	ServiceName string
	// TrustClientContext continues a caller's W3C traceparent. Off, every
	// request starts its own trace: a public caller can neither join a trace
	// nor force sampling (W3C Trace Context 3.4 and 7.2).
	TrustClientContext bool
	// Version is service.version.
	Version string
	// MetricInterval is how often metrics are pushed (default 60 s).
	MetricInterval time.Duration
}

// DefaultConfig holds the defaults of every flag.
func DefaultConfig() Config {
	return Config{Protocol: "http", SampleRatio: 1, ServiceName: "turnd", MetricInterval: time.Minute}
}

// Enabled reports whether an endpoint is configured.
func (c Config) Enabled() bool { return c.Endpoint != "" }

var (
	hostPort    = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}:[0-9]{1,5}$`)
	serviceName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Validate refuses a configuration that would leak or cannot work. A disabled
// configuration with any other telemetry flag set is refused too: it would be
// silently ignored.
func (c Config) Validate() error {
	if c.Endpoint == "" {
		if c.Token != "" || c.Insecure || c.TrustClientContext {
			return errors.New("--otel-token-file, --otel-insecure and --otel-trust-client-context need --otel-endpoint")
		}
		return nil
	}
	if !(c.SampleRatio >= 0 && c.SampleRatio <= 1) {
		return fmt.Errorf("--otel-sample-ratio %v: want 0..1", c.SampleRatio)
	}
	if !serviceName.MatchString(c.ServiceName) {
		return fmt.Errorf("--otel-service-name %q: want [A-Za-z0-9_.-]{1,64}", c.ServiceName)
	}
	var host string
	switch c.Protocol {
	case "http":
		u, err := url.Parse(c.Endpoint)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
			!(u.Scheme == "https" || u.Scheme == "http" && c.Insecure) {
			return fmt.Errorf("--otel-endpoint %q: want https://host:port without credentials, query or fragment (http:// only with --otel-insecure)", redactURL(c.Endpoint))
		}
		host = u.Hostname()
	case "grpc":
		if !hostPort.MatchString(c.Endpoint) {
			return errors.New("--otel-endpoint: want host:port for grpc (the value is not echoed: it may carry credentials)")
		}
		host = c.Endpoint[:strings.LastIndex(c.Endpoint, ":")]
	default:
		return fmt.Errorf("--otel-protocol %q: want grpc or http", c.Protocol)
	}
	if c.Token != "" && (c.Insecure || strings.HasPrefix(c.Endpoint, "http://")) && !isLoopbackHost(host) {
		return errors.New("--otel-token-file over plaintext to a non-loopback collector would send the token in clear")
	}
	return nil
}

// redactURL drops what a URL could carry that must not be printed.
func redactURL(s string) string {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return "(unparsable)"
}
