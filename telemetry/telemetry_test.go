package telemetry_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/go-turn/turn/internal/fakeotlp"
	"github.com/go-turn/turn/rendezvous"
	"github.com/go-turn/turn/server"
	"github.com/go-turn/turn/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func cfgFor(c *fakeotlp.Collector) telemetry.Config {
	cfg := telemetry.DefaultConfig()
	cfg.Endpoint, cfg.Insecure = c.URL, true
	cfg.MetricInterval, cfg.BatchInterval = 50*time.Millisecond, 20*time.Millisecond
	cfg.Version = "v9.9.9"
	return cfg
}

func setup(t *testing.T, cfg telemetry.Config) *telemetry.Telemetry {
	t.Helper()
	tel, err := telemetry.Setup(context.Background(), cfg, func(m string) { t.Log("warn:", m) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })
	return tel
}

// app is a tiny server with the routes turnd has, instrumented as turnd is.
func app(t *testing.T, tel *telemetry.Telemetry, logger *slog.Logger) *httptest.Server {
	t.Helper()
	m := tel.Metrics()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		m.LoginObserve(r.Context(), "started")
		logger.InfoContext(r.Context(), "login: session issued to SUBJECT-PSEUDONYM for origin https://x, until later")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		m.LoginObserve(r.Context(), "provider_error")
		logger.WarnContext(r.Context(), "login refused by the provider: \"access_denied\"")
		http.Error(w, "no", http.StatusBadRequest)
	})
	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) })
	srv := httptest.NewServer(tel.HTTP(mux, "/grpc"))
	t.Cleanup(srv.Close)
	return srv
}

func attrStr(sp *tracepb.Span, k string) string { v, _ := fakeotlp.Attr(sp.Attributes, k); return v }

func attrInt(kvs []*commonpb.KeyValue, k string) int64 {
	for _, kv := range kvs {
		if kv.Key == k {
			return kv.GetValue().GetIntValue()
		}
	}
	return -1
}

func spanNamed(c *fakeotlp.Collector, name string) *tracepb.Span {
	for _, s := range c.Spans() {
		if s.Name == name {
			return s
		}
	}
	return nil
}

func get(t *testing.T, url string, hdr map[string]string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestThreeSignalsOverHTTP(t *testing.T) {
	col := fakeotlp.New(t)
	tel := setup(t, cfgFor(col))
	logger := tel.Logger(&bytes.Buffer{}, slog.LevelInfo)
	tel.Metrics().BindRendezvous(func() rendezvous.Counts { return rendezvous.Counts{Rooms: 3, Pending: 1, Guests: 2} })
	tel.Metrics().BindRelay(func() server.Stats { return server.Stats{Allocations: 4, BytesToPeer: 10, PacketsToClient: 2} },
		func() server.Usage { return server.Usage{Permissions: 5, Channels: 6} })
	srv := app(t, tel, logger)
	get(t, srv.URL+"/login", nil)
	get(t, srv.URL+"/boom", nil)
	get(t, srv.URL+"/callback?code=c&state=s", nil)

	col.Wait(t, "spans, metrics and logs", func() bool {
		return spanNamed(col, "GET /login") != nil && spanNamed(col, "GET /boom") != nil && spanNamed(col, "GET /callback") != nil &&
			col.HasMetric("turnd.rooms") && col.HasMetric("turnd.relay.bytes") && col.HasMetric("http.server.request.duration") &&
			col.HasMetric("turnd.login.outcomes") && len(col.Logs()) >= 2
	})
	sp := spanNamed(col, "GET /login")
	if sp.Kind != tracepb.Span_SPAN_KIND_SERVER || attrStr(sp, "http.route") != "/login" || attrStr(sp, "turnd.outcome") != "started" ||
		attrInt(sp.Attributes, "http.response.status_code") != 200 || attrStr(sp, "http.request.method") != "GET" {
		t.Fatalf("login span: %v", sp)
	}
	if st := spanNamed(col, "GET /boom").Status; st.GetCode() != tracepb.Status_STATUS_CODE_ERROR {
		t.Fatalf("5xx must set Error: %v", st)
	}
	if st := spanNamed(col, "GET /callback").Status; st.GetCode() == tracepb.Status_STATUS_CODE_ERROR {
		t.Fatalf("4xx must leave the status unset: %v", st)
	}
	var withTrace bool
	for _, l := range col.Logs() {
		if strings.Contains(l.Body.GetStringValue(), "session issued to <redacted>") && len(l.TraceId) == 16 && bytes.Equal(l.TraceId, sp.TraceId) {
			withTrace = true
		}
	}
	if !withTrace {
		t.Fatalf("no log record correlated with the login span: %v", col.Logs())
	}
	for _, r := range col.Resources() {
		if v, _ := fakeotlp.Attr(r.Attributes, "service.name"); v != "turnd" {
			t.Fatalf("service.name %q", v)
		}
		if v, _ := fakeotlp.Attr(r.Attributes, "service.version"); v != "v9.9.9" {
			t.Fatalf("service.version %q", v)
		}
		if v, _ := fakeotlp.Attr(r.Attributes, "service.instance.id"); len(v) != 16 {
			t.Fatalf("service.instance.id %q", v)
		}
	}
}

func TestOverGRPC(t *testing.T) {
	col := fakeotlp.New(t)
	cfg := cfgFor(col)
	cfg.Protocol, cfg.Endpoint = "grpc", col.GRPCAddr
	tel := setup(t, cfg)
	logger := tel.Logger(&bytes.Buffer{}, slog.LevelInfo)
	srv := app(t, tel, logger)
	get(t, srv.URL+"/login", nil)
	col.Wait(t, "grpc spans, metrics and logs", func() bool {
		return spanNamed(col, "GET /login") != nil && col.HasMetric("http.server.request.duration") && len(col.Logs()) >= 1
	})
}

func TestBearerTokenFromFileOnly(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer ENVSECRET,x-api-key=ENVSECRET")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "authorization=Bearer ENVSECRET")
	for _, withToken := range []bool{true, false} {
		col := fakeotlp.New(t)
		cfg := cfgFor(col)
		var warned []string
		if withToken {
			cfg.Token = "file-token"
		}
		tel, err := telemetry.Setup(context.Background(), cfg, func(m string) { warned = append(warned, m) })
		if err != nil {
			t.Fatal(err)
		}
		if len(warned) < 2 || !strings.Contains(warned[0], "ignored") {
			t.Fatalf("the ignored environment must be reported: %v", warned)
		}
		srv := app(t, tel, tel.Logger(&bytes.Buffer{}, slog.LevelInfo))
		get(t, srv.URL+"/login", nil)
		col.Wait(t, "all three signals", func() bool {
			return spanNamed(col, "GET /login") != nil && len(col.Metrics()) > 0 && len(col.Logs()) > 0
		})
		if err := tel.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
		want := ""
		if withToken {
			want = "Bearer file-token"
		}
		auth := col.Auth()
		if len(auth) < 3 {
			t.Fatalf("want a request per signal, got %d", len(auth))
		}
		for _, a := range auth {
			if a != want {
				t.Fatalf("token %v: collector saw Authorization %q, want %q", withToken, a, want)
			}
		}
	}
}

func TestTraceContextRestartedUnlessTrusted(t *testing.T) {
	const tid, sid = "0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331"
	tp := map[string]string{"traceparent": "00-" + tid + "-" + sid + "-01"}
	for _, trust := range []bool{false, true} {
		col := fakeotlp.New(t)
		cfg := cfgFor(col)
		cfg.TrustClientContext = trust
		tel := setup(t, cfg)
		srv := app(t, tel, tel.Logger(&bytes.Buffer{}, slog.LevelInfo))
		get(t, srv.URL+"/login", tp)
		col.Wait(t, "span", func() bool { return spanNamed(col, "GET /login") != nil })
		sp := spanNamed(col, "GET /login")
		got := make([]byte, 0, 32)
		for _, b := range sp.TraceId {
			got = append(got, "0123456789abcdef"[b>>4], "0123456789abcdef"[b&15])
		}
		joined := string(got) == tid
		if trust && (!joined || len(sp.ParentSpanId) != 8) {
			t.Fatalf("trusted caller: the trace must continue (trace %s, parent %x)", got, sp.ParentSpanId)
		}
		if !trust && (joined || len(sp.ParentSpanId) != 0) {
			t.Fatalf("untrusted caller: the trace must restart (trace %s, parent %x)", got, sp.ParentSpanId)
		}
	}
}

func TestRelayRequestSpansAndMetrics(t *testing.T) {
	col := fakeotlp.New(t)
	tel := setup(t, cfgFor(col))
	now := time.Now()
	obs := tel.Metrics().ServerObserver()
	obs.Request(server.RequestInfo{Method: "create_permission", Transport: "tls", Code: 403, Policy: "metadata", Received: now.Add(-time.Millisecond), End: now})
	obs.Request(server.RequestInfo{Method: "allocate", Transport: "udp", Code: 438, Received: now, End: now})
	col.Wait(t, "relay spans and metrics", func() bool {
		return spanNamed(col, "TURN create_permission") != nil && spanNamed(col, "TURN allocate") != nil &&
			col.HasMetric("turnd.relay.requests") && col.HasMetric("turnd.relay.policy.refusals") && col.HasMetric("turnd.relay.auth.failures")
	})
	sp := spanNamed(col, "TURN create_permission")
	if attrStr(sp, "turnd.policy") != "metadata" || attrStr(sp, "turnd.result") != "forbidden" || attrStr(sp, "turnd.transport") != "tls" || len(sp.ParentSpanId) != 0 {
		t.Fatalf("span: %v", sp)
	}
	if d := time.Duration(sp.EndTimeUnixNano - sp.StartTimeUnixNano); d < time.Millisecond {
		t.Fatalf("the span must cover the request, lasted %v", d)
	}
}

func TestPrivateDataNeverReachesTheCollector(t *testing.T) {
	col := fakeotlp.New(t)
	tel := setup(t, cfgFor(col))
	logger := tel.Logger(&bytes.Buffer{}, slog.LevelDebug)
	srv := app(t, tel, logger)
	secrets := []string{"SECRETCODE", "SECRETSTATE", "SECRETTOKEN", "ROOMCAPABILITY32HEXCHARS", "1700000000:HMACUSERNAME",
		"203.0.113.9", "198.51.100.7", "COOKIEVALUE", "INBOUNDBEARER", "https://go-tex.github.io", "SUBJECT-PSEUDONYM", "127.0.0.1"}
	get(t, srv.URL+"/callback?code=SECRETCODE&state=SECRETSTATE", map[string]string{
		"Cookie": "turnd_flow=COOKIEVALUE", "Authorization": "Bearer INBOUNDBEARER", "Origin": "https://go-tex.github.io",
		"X-Forwarded-For": "203.0.113.9", "Referer": "https://x.example/?code=SECRETCODE"})
	get(t, srv.URL+"/login", nil)
	ctx := context.Background()
	logger.Warn("with attributes", "token", "SECRETTOKEN", "room", "ROOMCAPABILITY32HEXCHARS", "user", "1700000000:HMACUSERNAME",
		"client", netip.MustParseAddrPort("203.0.113.9:4444"), "peer", "198.51.100.7:1234", "nested", slog.GroupValue(slog.String("addr", "203.0.113.9")),
		"note", "198.51.100.7")
	logger.Debug("peer refused", "code", 403, "peer", netip.MustParseAddrPort("198.51.100.7:9"), "client", "203.0.113.9:1")
	logger.With("client", "203.0.113.9").InfoContext(ctx, "bound attribute")
	// what the SDK instrumentation may add on its own
	_, sp := tel.TracerProvider().Tracer("t").Start(ctx, "rpc")
	sp.SetAttributes(attribute.String("network.peer.address", "203.0.113.9"), attribute.Int("network.peer.port", 4444),
		attribute.String("url.query", "code=SECRETCODE"), attribute.String("whatever", "198.51.100.7:1234"),
		attribute.String("kept", "fine"))
	sp.AddEvent("message", trace.WithAttributes(eventAttrs()...))
	sp.End()

	col.Wait(t, "everything", func() bool {
		return spanNamed(col, "GET /callback") != nil && spanNamed(col, "rpc") != nil && len(col.Logs()) >= 4 && col.HasMetric("turnd.login.outcomes")
	})
	if err := tel.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	raw := col.Raw()
	for _, s := range secrets {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("%q reached the collector", s)
		}
	}
	// the positive controls: what is allowed does arrive
	rpc := spanNamed(col, "rpc")
	if attrStr(rpc, "kept") != "fine" || attrStr(rpc, "network.peer.address") != "" {
		t.Fatalf("scrub: %v", rpc.Attributes)
	}
	var sawPlain bool
	for _, l := range col.Logs() {
		if l.Body.GetStringValue() == "bound attribute" || l.Body.GetStringValue() == "with attributes" {
			sawPlain = true
		}
		if strings.Contains(l.Body.GetStringValue(), "peer refused") {
			t.Fatalf("a debug record must not be exported")
		}
	}
	if !sawPlain {
		t.Fatal("the info records must be exported")
	}
}

func eventAttrs() []attribute.KeyValue {
	return []attribute.KeyValue{attribute.String("client.address", "203.0.113.9"), attribute.Int("message.id", 1)}
}

func TestDisabledIsInert(t *testing.T) {
	tel, err := telemetry.Setup(context.Background(), telemetry.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if tel.Enabled() {
		t.Fatal("no endpoint means off")
	}
	var h http.Handler = http.NotFoundHandler()
	if tel.HTTP(h) == nil {
		t.Fatal("HTTP must return a handler")
	}
	var buf bytes.Buffer
	tel.Logger(&buf, slog.LevelInfo).Info("hello")
	if !strings.Contains(buf.String(), `"msg":"hello"`) {
		t.Fatalf("the JSON log works with telemetry off: %q", buf.String())
	}
	if err := tel.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLogsCarryTraceAndSpanIDsOnStderr(t *testing.T) {
	col := fakeotlp.New(t)
	tel := setup(t, cfgFor(col))
	var buf bytes.Buffer
	logger := tel.Logger(&buf, slog.LevelInfo)
	srv := app(t, tel, logger)
	get(t, srv.URL+"/login", nil)
	if !strings.Contains(buf.String(), `"trace_id":"`) || !strings.Contains(buf.String(), `"span_id":"`) {
		t.Fatalf("stderr JSON lacks trace_id/span_id: %s", buf.String())
	}
	// stderr keeps what the collector does not get: the subject.
	if !strings.Contains(buf.String(), "SUBJECT-PSEUDONYM") {
		t.Fatalf("stderr must keep the operator's login line: %s", buf.String())
	}
}

func TestConfigValidate(t *testing.T) {
	base := telemetry.DefaultConfig()
	ok := func(mut func(*telemetry.Config)) telemetry.Config { c := base; mut(&c); return c }
	cases := []struct {
		name string
		cfg  telemetry.Config
		want string // substring of the error; "" is valid
	}{
		{"off", base, ""},
		{"https", ok(func(c *telemetry.Config) { c.Endpoint = "https://otel.example:4318" }), ""},
		{"http needs insecure", ok(func(c *telemetry.Config) { c.Endpoint = "http://otel.example:4318" }), "https"},
		{"http insecure", ok(func(c *telemetry.Config) { c.Endpoint, c.Insecure = "http://otel.example:4318", true }), ""},
		{"credentials in the URL", ok(func(c *telemetry.Config) { c.Endpoint = "https://u:p@otel.example:4318" }), "without credentials"},
		{"query in the URL", ok(func(c *telemetry.Config) { c.Endpoint = "https://otel.example:4318/?token=abc" }), "without credentials"},
		{"grpc", ok(func(c *telemetry.Config) { c.Protocol, c.Endpoint = "grpc", "otel.example:4317" }), ""},
		{"grpc userinfo", ok(func(c *telemetry.Config) { c.Protocol, c.Endpoint = "grpc", "u:p@otel.example:4317" }), "host:port"},
		{"bad protocol", ok(func(c *telemetry.Config) { c.Protocol, c.Endpoint = "ftp", "x:1" }), "grpc or http"},
		{"ratio", ok(func(c *telemetry.Config) { c.Endpoint, c.SampleRatio = "https://o:1", 1.5 }), "0..1"},
		{"service name", ok(func(c *telemetry.Config) { c.Endpoint, c.ServiceName = "https://o:1", "bad name" }), "service-name"},
		{"token in clear", ok(func(c *telemetry.Config) { c.Endpoint, c.Insecure, c.Token = "http://otel.example:4318", true, "t" }), "in clear"},
		{"token to loopback", ok(func(c *telemetry.Config) { c.Endpoint, c.Insecure, c.Token = "http://127.0.0.1:4318", true, "t" }), ""},
		{"flags without endpoint", ok(func(c *telemetry.Config) { c.TrustClientContext = true }), "need --otel-endpoint"},
	}
	for _, tc := range cases {
		err := tc.cfg.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error %v, want %q", tc.name, err, tc.want)
		case err != nil && (strings.Contains(err.Error(), "p@") || strings.Contains(err.Error(), "abc")):
			t.Errorf("%s: the error echoes a credential: %v", tc.name, err)
		}
	}
}
