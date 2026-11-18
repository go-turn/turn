package telemetry

import (
	"context"
	"sync/atomic"

	"github.com/go-turn/turn/rendezvous"
	"github.com/go-turn/turn/server"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// The instruments, one per fact. Names are turnd.*; units are UCUM ({thing}
// for a count, By for bytes, s for seconds). Every attribute has a small fixed
// set of values: nothing here is a person, a credential or an address.
//
//	turnd.relay.allocations            gauge    {allocation}  live TURN allocations
//	turnd.relay.permissions            gauge    {permission}  live permissions
//	turnd.relay.channels               gauge    {channel}     live channel bindings
//	turnd.relay.requests               counter  {request}     control requests by turnd.method, turnd.transport, turnd.result
//	turnd.relay.policy.refusals        counter  {refusal}     peer-address refusals by turnd.policy
//	turnd.relay.auth.failures          counter  {failure}     by turnd.surface (relay, api) and turnd.reason
//	turnd.relay.bytes                  counter  By            relayed payload by turnd.direction
//	turnd.relay.packets                counter  {packet}      relayed datagrams by turnd.direction
//	turnd.relay.packets.dropped        counter  {packet}      datagrams dropped (no permission, rate cap, bad frame)
//	turnd.rooms                        gauge    {room}        live rooms
//	turnd.guests                       gauge    {guest}       by turnd.state (pending, admitted)
//	turnd.rendezvous.operations        counter  {operation}   by turnd.action and turnd.outcome
//	turnd.login.outcomes               counter  {login}       by turnd.outcome
//	http.server.request.duration       histogram s            /login, /callback, /healthz (HTTP semantic conventions)
//
// What other signals are derived from these: allocations created and refused
// are turnd.relay.requests{method=allocate} with result ok or the refusal;
// knocks, admits and denies are turnd.rendezvous.operations{action=knock,
// admit, deny}; credentials minted are the operations credentials_host and
// credentials_room with outcome ok; sessions issued and refused are
// turnd.login.outcomes. The gRPC instrumentation adds rpc.server.* on its own.
type Metrics struct {
	tracer trace.Tracer

	requests, policy, authFail, ops, login metric.Int64Counter
	httpDur                                metric.Float64Histogram

	relay atomic.Pointer[relaySource]
	rv    atomic.Pointer[func() rendezvous.Counts]
}

type relaySource struct {
	stats func() server.Stats
	usage func() server.Usage
}

var (
	attrDirToPeer   = metric.WithAttributes(attribute.String("turnd.direction", "client_to_peer"))
	attrDirToClient = metric.WithAttributes(attribute.String("turnd.direction", "peer_to_client"))
)

func newMetrics(m metric.Meter, tr trace.Tracer) *Metrics {
	x := &Metrics{tracer: tr}
	x.requests, _ = m.Int64Counter("turnd.relay.requests", metric.WithUnit("{request}"),
		metric.WithDescription("TURN control requests by method, transport and result"))
	x.policy, _ = m.Int64Counter("turnd.relay.policy.refusals", metric.WithUnit("{refusal}"),
		metric.WithDescription("TURN peer addresses refused by policy, by class"))
	x.authFail, _ = m.Int64Counter("turnd.relay.auth.failures", metric.WithUnit("{failure}"),
		metric.WithDescription("authentication failures by surface and reason; relay 401 includes the initial RFC 8489 challenge"))
	x.ops, _ = m.Int64Counter("turnd.rendezvous.operations", metric.WithUnit("{operation}"),
		metric.WithDescription("rendezvous RPCs by action and outcome"))
	x.login, _ = m.Int64Counter("turnd.login.outcomes", metric.WithUnit("{login}"),
		metric.WithDescription("OIDC login starts and callbacks by outcome"))
	x.httpDur, _ = m.Float64Histogram("http.server.request.duration", metric.WithUnit("s"),
		metric.WithDescription("Duration of HTTP server requests"),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10))

	relayGauge := func(name, unit, desc string, get func(*relaySource) int64) {
		g, _ := m.Int64ObservableGauge(name, metric.WithUnit(unit), metric.WithDescription(desc))
		_, _ = m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
			if s := x.relay.Load(); s != nil {
				o.ObserveInt64(g, get(s))
			}
			return nil
		}, g)
	}
	relayGauge("turnd.relay.allocations", "{allocation}", "live TURN allocations", func(s *relaySource) int64 { return int64(s.stats().Allocations) })
	relayGauge("turnd.relay.permissions", "{permission}", "live TURN permissions", func(s *relaySource) int64 { return int64(s.usage().Permissions) })
	relayGauge("turnd.relay.channels", "{channel}", "live TURN channel bindings", func(s *relaySource) int64 { return int64(s.usage().Channels) })

	// The relay's own counters are read at export time: the hot path pays for
	// them whether or not telemetry is on.
	bytesC, _ := m.Int64ObservableCounter("turnd.relay.bytes", metric.WithUnit("By"), metric.WithDescription("relayed payload bytes"))
	pktC, _ := m.Int64ObservableCounter("turnd.relay.packets", metric.WithUnit("{packet}"), metric.WithDescription("relayed datagrams"))
	dropC, _ := m.Int64ObservableCounter("turnd.relay.packets.dropped", metric.WithUnit("{packet}"), metric.WithDescription("datagrams dropped"))
	_, _ = m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		s := x.relay.Load()
		if s == nil {
			return nil
		}
		st := s.stats()
		o.ObserveInt64(bytesC, int64(st.BytesToPeer), attrDirToPeer)
		o.ObserveInt64(bytesC, int64(st.BytesToClient), attrDirToClient)
		o.ObserveInt64(pktC, int64(st.PacketsToPeer), attrDirToPeer)
		o.ObserveInt64(pktC, int64(st.PacketsToClient), attrDirToClient)
		o.ObserveInt64(dropC, int64(st.Dropped))
		return nil
	}, bytesC, pktC, dropC)

	rooms, _ := m.Int64ObservableGauge("turnd.rooms", metric.WithUnit("{room}"), metric.WithDescription("live rooms"))
	guests, _ := m.Int64ObservableGauge("turnd.guests", metric.WithUnit("{guest}"), metric.WithDescription("guests by state"))
	_, _ = m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		f := x.rv.Load()
		if f == nil {
			return nil
		}
		c := (*f)()
		o.ObserveInt64(rooms, int64(c.Rooms))
		o.ObserveInt64(guests, int64(c.Pending), metric.WithAttributes(attribute.String("turnd.state", "pending")))
		o.ObserveInt64(guests, int64(c.Guests), metric.WithAttributes(attribute.String("turnd.state", "admitted")))
		return nil
	}, rooms, guests)
	return x
}

// BindRelay tells the gauges where the relay's counters are. Call it once the
// relay exists.
func (m *Metrics) BindRelay(stats func() server.Stats, usage func() server.Usage) {
	m.relay.Store(&relaySource{stats, usage})
}

// BindRendezvous tells the gauges where the rooms are.
func (m *Metrics) BindRendezvous(counts func() rendezvous.Counts) { m.rv.Store(&counts) }

// errName names a STUN error code (RFC 8489 section 14.8, RFC 8656 section 19).
func errName(code int) string {
	switch code {
	case 0:
		return "ok"
	case 400:
		return "bad_request"
	case 401:
		return "unauthenticated"
	case 403:
		return "forbidden"
	case 420:
		return "unknown_attribute"
	case 437:
		return "allocation_mismatch"
	case 438:
		return "stale_nonce"
	case 440:
		return "address_family_not_supported"
	case 441:
		return "wrong_credentials"
	case 442:
		return "unsupported_transport"
	case 443:
		return "peer_address_family_mismatch"
	case 486:
		return "allocation_quota_reached"
	case 508:
		return "insufficient_capacity"
	}
	return "other"
}

// ServerObserver is the relay's observer: server.Config.Observer.
func (m *Metrics) ServerObserver() server.Observer { return relayObserver{m} }

type relayObserver struct{ m *Metrics }

func (o relayObserver) Request(r server.RequestInfo) {
	ctx := context.Background()
	res := errName(r.Code)
	o.m.requests.Add(ctx, 1, metric.WithAttributes(
		attribute.String("turnd.method", r.Method), attribute.String("turnd.transport", r.Transport),
		attribute.String("turnd.result", res)))
	switch r.Code {
	case 401, 438, 441:
		o.m.authFail.Add(ctx, 1, metric.WithAttributes(attribute.String("turnd.surface", "relay"), attribute.String("turnd.reason", res)))
	}
	if r.Policy != "" {
		o.m.policy.Add(ctx, 1, metric.WithAttributes(attribute.String("turnd.policy", r.Policy)))
	}
	// A short root span per control request, timed from the moment the request
	// was read. The sampler decides; an unsampled span is a few ns.
	_, sp := o.m.tracer.Start(ctx, "TURN "+r.Method, trace.WithNewRoot(), trace.WithSpanKind(trace.SpanKindServer),
		trace.WithTimestamp(r.Received))
	if sp.IsRecording() {
		sp.SetAttributes(attribute.String("turnd.method", r.Method), attribute.String("turnd.transport", r.Transport),
			attribute.String("turnd.result", res))
		if r.Code != 0 {
			sp.SetAttributes(attribute.Int("turnd.stun.error_code", r.Code), attribute.String("error.type", res))
		}
		if r.Policy != "" {
			sp.SetAttributes(attribute.String("turnd.policy", r.Policy))
		}
	}
	sp.End(trace.WithTimestamp(r.End))
}

// RendezvousObserver is rendezvous.Config.Observer.
func (m *Metrics) RendezvousObserver() rendezvous.Observer { return rvObserver{m} }

type rvObserver struct{ m *Metrics }

func (o rvObserver) Event(ctx context.Context, action, outcome string) {
	o.m.ops.Add(ctx, 1, metric.WithAttributes(attribute.String("turnd.action", action), attribute.String("turnd.outcome", outcome)))
	if sp := trace.SpanFromContext(ctx); sp.IsRecording() {
		sp.SetAttributes(attribute.String("turnd.room.action", action), attribute.String("turnd.outcome", outcome))
	}
}

// LoginObserve is session.LoginConfig.Observe.
func (m *Metrics) LoginObserve(ctx context.Context, outcome string) {
	m.login.Add(ctx, 1, metric.WithAttributes(attribute.String("turnd.outcome", outcome)))
	if sp := trace.SpanFromContext(ctx); sp.IsRecording() {
		sp.SetAttributes(attribute.String("turnd.outcome", outcome))
	}
}

// AuthObserve is session.Auth.Observe: why a token was refused. The reason is
// a fixed word, never the verifier's error text.
func (m *Metrics) AuthObserve(ctx context.Context, reason string) {
	m.authFail.Add(ctx, 1, metric.WithAttributes(attribute.String("turnd.surface", "api"), attribute.String("turnd.reason", reason)))
	if sp := trace.SpanFromContext(ctx); sp.IsRecording() {
		sp.SetAttributes(attribute.String("turnd.refusal", reason))
	}
}
