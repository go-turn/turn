package main

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-turn/turn/internal/fakeotlp"
	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestOpenTelemetryEndToEnd drives the real daemon (login, WebSocket gRPC,
// refusals) against an in-process OTLP collector and asserts what arrives:
// the spans, the metrics, the correlated logs, the collector bearer token and,
// above all, that no secret and no address of the test client does.
func TestOpenTelemetryEndToEnd(t *testing.T) {
	oldM, oldB := otelMetricInterval, otelBatchInterval
	otelMetricInterval, otelBatchInterval = 50*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { otelMetricInterval, otelBatchInterval = oldM, oldB })
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer ENVSECRET")

	col := fakeotlp.New(t)
	d := run(t, "--otel-endpoint", col.URL, "--otel-insecure", "--otel-service-name", "turnd-test",
		"--otel-token-file", writeSecret(t, "otok", "collector-token-xyz", 0o600))

	// a login that works, one that is refused at the door, an unknown path
	token, _ := d.login(t)
	if resp, err := http.Get(d.base + "/login?origin=" + url.QueryEscape("https://evil.example")); err != nil || resp.StatusCode != 400 {
		t.Fatalf("%v %v", resp, err)
	}
	d.get(t, "/healthz")
	d.get(t, "/nope")

	rpc := d.dial(t, origin)
	room, err := rpc.CreateRoom(rctx(t, token), &turnv1.CreateRoomRequest{})
	if err != nil {
		t.Fatal(err)
	}
	guest, err := rpc.JoinRoom(rctx(t, ""), &turnv1.JoinRoomRequest{Room: room.Room, Name: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rpc.Admit(rctx(t, room.Token), &turnv1.DecideRequest{Room: room.Room, Peer: guest.Peer}); err != nil {
		t.Fatal(err)
	}
	cr, err := rpc.RoomCredentials(rctx(t, guest.Token), &turnv1.RoomRef{Room: room.Room})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rpc.Credentials(rctx(t, "garbage-token-not-ours"), &turnv1.CredentialsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("%v", err)
	}

	has := func(name string) bool { return spanNamed(col, name) != nil }
	col.Wait(t, "spans, metrics and logs", func() bool {
		return has("GET /login") && has("GET /callback") && has("GET /healthz") && rpcSpan(col, "CreateRoom") != nil && rpcSpan(col, "RoomCredentials") != nil &&
			col.HasMetric("turnd.login.outcomes") && col.HasMetric("turnd.rendezvous.operations") && col.HasMetric("turnd.rooms") &&
			col.HasMetric("turnd.relay.auth.failures") && col.HasMetric("http.server.request.duration") && hasPrefixMetric(col, "rpc.server.") &&
			logWith(col, "session issued to <redacted>") != nil
	})

	if sp := rpcSpan(col, "CreateRoom"); attr(sp, "turnd.room.action") != "create_room" || attr(sp, "turnd.outcome") != "ok" || sp.Kind != tracepb.Span_SPAN_KIND_SERVER {
		t.Fatalf("CreateRoom span: %v", sp)
	}
	var sawRefusal, sawIssued bool
	for _, s := range col.Spans() {
		if s.Name == "GET /login" && attr(s, "turnd.outcome") == "origin_refused" {
			sawRefusal = true
		}
		if s.Name == "GET /callback" && attr(s, "turnd.outcome") == "issued" {
			sawIssued = true
			if l := logWith(col, "session issued to <redacted>"); !bytes.Equal(l.TraceId, s.TraceId) || !bytes.Equal(l.SpanId, s.SpanId) {
				t.Fatalf("the login log line must carry the callback span's ids")
			}
		}
		if strings.Contains(s.Name, "/nope") {
			t.Fatalf("an unknown path became a span name: %q", s.Name)
		}
	}
	if !sawRefusal || !sawIssued {
		t.Fatalf("login outcome attributes missing: refused=%v issued=%v", sawRefusal, sawIssued)
	}
	for _, r := range col.Resources() {
		if v, _ := fakeotlp.Attr(r.Attributes, "service.name"); v != "turnd-test" {
			t.Fatalf("service.name %q", v)
		}
	}

	// bearer: the file's token on every request, never the environment's
	for _, a := range col.Auth() {
		if a != "Bearer collector-token-xyz" {
			t.Fatalf("collector saw Authorization %q", a)
		}
	}
	if !strings.Contains(d.errs.String(), "OTEL_EXPORTER_OTLP_HEADERS is set and ignored") {
		t.Fatalf("the ignored environment must be reported on stderr: %s", d.errs)
	}

	// the JSON log on stderr, with ids
	if !strings.Contains(d.errs.String(), `"trace_id":"`) || !strings.Contains(d.errs.String(), "session issued to") {
		t.Fatalf("stderr: %s", d.errs)
	}

	// privacy: nothing secret, nobody's address
	raw := col.Raw()
	ice := cr.IceServers[len(cr.IceServers)-1]
	for _, s := range []string{token, room.Room, room.Token, guest.Token, ice.Username, ice.Credential,
		"collector-token-xyz", "ENVSECRET", "client-s3cret", sessionKey, turnSecret, "garbage-token-not-ours", "127.0.0.1", "Bob"} {
		if s != "" && bytes.Contains(raw, []byte(s)) {
			t.Errorf("%q reached the collector", s)
		}
	}
}

func spanNamed(c *fakeotlp.Collector, name string) *tracepb.Span {
	for _, s := range c.Spans() {
		if s.Name == name {
			return s
		}
	}
	return nil
}

func rpcSpan(c *fakeotlp.Collector, method string) *tracepb.Span {
	for _, s := range c.Spans() {
		if strings.HasSuffix(s.Name, "/"+method) {
			return s
		}
	}
	return nil
}

func attr(s *tracepb.Span, k string) string { v, _ := fakeotlp.Attr(s.Attributes, k); return v }

func hasPrefixMetric(c *fakeotlp.Collector, prefix string) bool {
	for _, m := range c.Metrics() {
		if strings.HasPrefix(m.Name, prefix) {
			return true
		}
	}
	return false
}

func logWith(c *fakeotlp.Collector, sub string) *logspb.LogRecord {
	for _, l := range c.Logs() {
		if strings.Contains(l.Body.GetStringValue(), sub) {
			return l
		}
	}
	return nil
}
