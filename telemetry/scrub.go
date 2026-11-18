package telemetry

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// deniedKeys are attribute keys that never leave the process, whoever adds
// them (the gRPC instrumentation records the peer's address by itself, for
// one). They name addresses of people and the places a secret travels.
var deniedKeys = []attribute.Key{
	"network.peer.address", "network.peer.port", "network.local.address", "network.local.port",
	"client.address", "client.port", "source.address", "source.port",
	"net.peer.ip", "net.peer.name", "net.peer.port", "net.sock.peer.addr", "net.sock.peer.port",
	"net.host.ip", "net.sock.host.addr", "net.sock.host.port",
	"http.client_ip", "http.user_agent", "user_agent.original", "http.target", "http.url", "url.full",
	"url.query", "url.fragment", "http.request.header.authorization", "http.request.header.cookie",
	"http.request.header.origin", "http.request.header.referer",
}

var deniedSet = func() map[attribute.Key]struct{} {
	m := make(map[attribute.Key]struct{}, len(deniedKeys))
	for _, k := range deniedKeys {
		m[k] = struct{}{}
	}
	return m
}()

// looksLikeAddress reports whether s is an IP address or an address with a
// port: a value that must not be exported under any key.
func looksLikeAddress(s string) bool {
	if len(s) > 64 || s == "" {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParseAddrPort(s); err == nil {
		return true
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		_, err := netip.ParseAddr(h)
		return err == nil
	}
	return false
}

func keep(kv attribute.KeyValue) bool {
	if _, bad := deniedSet[kv.Key]; bad {
		return false
	}
	if kv.Value.Type() == attribute.STRING && looksLikeAddress(kv.Value.AsString()) {
		return false
	}
	return true
}

func filterKVs(in []attribute.KeyValue) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(in))
	for _, kv := range in {
		if keep(kv) {
			out = append(out, kv)
		}
	}
	return out
}

// scrubExporter wraps a span exporter and removes the denied attributes from
// every span and span event before they are encoded.
type scrubExporter struct{ sdktrace.SpanExporter }

type scrubSpan struct{ sdktrace.ReadOnlySpan }

func (s scrubSpan) Attributes() []attribute.KeyValue { return filterKVs(s.ReadOnlySpan.Attributes()) }
func (s scrubSpan) Events() []sdktrace.Event {
	ev := s.ReadOnlySpan.Events()
	out := make([]sdktrace.Event, len(ev))
	for i, e := range ev {
		e.Attributes = filterKVs(e.Attributes)
		out[i] = e
	}
	return out
}

func (e scrubExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	cp := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		cp[i] = scrubSpan{s}
	}
	return e.SpanExporter.ExportSpans(ctx, cp)
}

// deniedLogKeys are slog attribute keys never exported. The server's debug
// records name the client, the peer and the TURN username; the others are the
// places a secret would be logged by mistake.
var deniedLogKeys = []string{
	"user", "username", "client", "peer", "from", "to", "remote", "relay", "proxy", "addr", "address", "ip",
	"token", "code", "state", "cookie", "credential", "password", "secret", "authorization", "nonce",
	"key", "room", "origin", "subject",
}

const maxLogBody = 512

// subjectRE finds the pseudonymous subject in the login and renewal lines.
var subjectRE = regexp.MustCompile(`((?:session issued to|session renewed for|renewal refused for|renewal refused by the provider for|renewal for) )[^\s:,]+`)

// redactHandler sits in front of the OTLP log handler. It exports Info and
// above only (the debug records carry addresses), cuts the message, and drops
// the attributes that are denied by key or are addresses by value.
type redactHandler struct{ next slog.Handler }

func (h redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= slog.LevelInfo && h.next.Enabled(ctx, l)
}

func deniedLogKey(k string) bool {
	k = strings.ToLower(k)
	for _, d := range deniedLogKeys {
		if k == d || strings.HasSuffix(k, "."+d) || strings.HasSuffix(k, "_"+d) {
			return true
		}
	}
	return false
}

func cleanAttr(a slog.Attr) (slog.Attr, bool) {
	a.Value = a.Value.Resolve()
	if deniedLogKey(a.Key) {
		return a, false
	}
	switch a.Value.Kind() {
	case slog.KindGroup:
		var kept []slog.Attr
		for _, g := range a.Value.Group() {
			if c, ok := cleanAttr(g); ok {
				kept = append(kept, c)
			}
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(kept...)}, len(kept) > 0
	case slog.KindString:
		if looksLikeAddress(a.Value.String()) {
			return a, false
		}
	case slog.KindAny:
		switch a.Value.Any().(type) {
		case netip.Addr, netip.AddrPort, net.Addr, net.IP:
			return a, false
		}
	}
	return a, true
}

func (h redactHandler) Handle(ctx context.Context, r slog.Record) error {
	// The login line names the pseudonymous subject; stderr keeps it, the
	// collector does not get it.
	msg := subjectRE.ReplaceAllString(r.Message, "${1}<redacted>")
	if len(msg) > maxLogBody {
		msg = msg[:maxLogBody]
	}
	c := slog.NewRecord(r.Time, r.Level, strings.ToValidUTF8(msg, ""), 0)
	r.Attrs(func(a slog.Attr) bool {
		if k, ok := cleanAttr(a); ok {
			c.AddAttrs(k)
		}
		return true
	})
	return h.next.Handle(ctx, c)
}

func (h redactHandler) WithAttrs(as []slog.Attr) slog.Handler {
	var kept []slog.Attr
	for _, a := range as {
		if c, ok := cleanAttr(a); ok {
			kept = append(kept, c)
		}
	}
	return redactHandler{h.next.WithAttrs(kept)}
}

func (h redactHandler) WithGroup(n string) slog.Handler { return redactHandler{h.next.WithGroup(n)} }
