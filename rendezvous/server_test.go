package rendezvous

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-turn/turn/creds"
	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

var base = time.Unix(1_800_000_000, 0)

type fix struct {
	t     *testing.T
	s     *Server
	c     turnv1.TurndClient
	ring  *creds.Keyring
	off   atomic.Int64 // seconds the clock has advanced
	hosts map[string]string
}

func (f *fix) now() time.Time { return base.Add(time.Duration(f.off.Load()) * time.Second) }

func newFix(t *testing.T, mod func(*Config)) *fix {
	t.Helper()
	f := &fix{t: t, hosts: map[string]string{}}
	f.ring, _ = creds.NewKeyring([]byte("0123456789abcdef0123"))
	cfg := Config{
		Auth: func(_ context.Context, tok string) (string, error) {
			if s, ok := strings.CutPrefix(tok, "user:"); ok && s != "" {
				return s, nil
			}
			return "", errors.New("no")
		},
		Keyring: f.ring, STUN: []string{"stun:t.example:3478"}, TURN: []string{"turn:t.example:3478?transport=udp"},
		Now: f.now,
	}
	if mod != nil {
		mod(&cfg)
	}
	var err error
	if f.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.MaxRecvMsgSize(f.s.MaxRecvMsgSize()))
	f.s.Register(gs)
	lis := bufconn.Listen(1 << 20)
	go func() { _ = gs.Serve(lis) }()
	cc, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close(); gs.Stop() })
	f.c = turnv1.NewTurndClient(cc)
	return f
}

func tctx(t *testing.T, token string, kv ...string) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	md := metadata.MD{}
	if token != "" {
		md.Set("authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		md.Set(kv[i], kv[i+1])
	}
	return metadata.NewOutgoingContext(ctx, md)
}

func code(err error) codes.Code { return status.Code(err) }

func (f *fix) create(user string) *turnv1.CreateRoomResponse {
	f.t.Helper()
	r, err := f.c.CreateRoom(tctx(f.t, "user:"+user), &turnv1.CreateRoomRequest{})
	if err != nil {
		f.t.Fatalf("create: %v", err)
	}
	f.hosts[r.Room] = r.Token
	return r
}

// knock joins as a pending guest.
func (f *fix) knock(room, name string) *turnv1.JoinRoomResponse {
	f.t.Helper()
	j, err := f.c.JoinRoom(tctx(f.t, ""), &turnv1.JoinRoomRequest{Room: room, Name: name})
	if err != nil {
		f.t.Fatalf("join: %v", err)
	}
	if !j.Pending {
		f.t.Fatal("a new guest is not pending")
	}
	return j
}

// join knocks and has the host admit the guest.
func (f *fix) join(room string) *turnv1.JoinRoomResponse {
	f.t.Helper()
	j := f.knock(room, "")
	if err := f.decide("admit", room, j.Peer); err != nil {
		f.t.Fatalf("admit: %v", err)
	}
	return j
}

func (f *fix) decide(verb, room, peer string) error {
	return f.decideAs(verb, room, f.hosts[room], peer)
}

func (f *fix) decideAs(verb, room, token, peer string) error {
	f.t.Helper()
	req := &turnv1.DecideRequest{Room: room, Peer: peer}
	var err error
	if verb == "admit" {
		_, err = f.c.Admit(tctx(f.t, token), req)
	} else {
		_, err = f.c.Deny(tctx(f.t, token), req)
	}
	return err
}

// ps is an open Room stream.
type ps struct {
	st  grpc.BidiStreamingClient[turnv1.Envelope, turnv1.Envelope]
	ev  chan *turnv1.Envelope
	end chan error // the stream's final error (nil for a clean end)
}

// open opens the Room stream. A refused open shows up as the first Recv error.
func (f *fix) open(room, token string) *ps {
	f.t.Helper()
	ctx, cancel := context.WithCancel(tctx(f.t, token, RoomMetadata, room))
	f.t.Cleanup(cancel)
	st, err := f.c.Room(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	p := &ps{st: st, ev: make(chan *turnv1.Envelope, 256), end: make(chan error, 1)}
	go func() {
		for {
			e, err := st.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				close(p.ev)
				p.end <- err
				return
			}
			p.ev <- e
		}
	}()
	// A client stream is lazy: wait until the server's handler has registered it
	// (or the stream has already ended), so that what the test does next cannot
	// overtake the open.
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline) && len(p.end) == 0; time.Sleep(time.Millisecond) {
		if f.streaming(room, token) {
			break
		}
	}
	return p
}

func (f *fix) streaming(room, token string) bool {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	rm := f.s.rooms[room]
	if rm == nil {
		return false
	}
	for _, p := range rm.peers {
		if p.token == token && p.streaming {
			return true
		}
	}
	return false
}

func (p *ps) send(from, to, kind string, body []byte) {
	_ = p.st.Send(&turnv1.Envelope{From: from, To: to, Kind: kind, Body: body})
}

func (p *ps) next(t *testing.T) *turnv1.Envelope {
	t.Helper()
	select {
	case e, ok := <-p.ev:
		if !ok {
			t.Fatal("stream ended")
		}
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("no event")
	}
	return nil
}

func (p *ps) nothing(t *testing.T) {
	t.Helper()
	select {
	case e, ok := <-p.ev:
		if ok {
			t.Fatalf("unexpected event %v", e)
		}
	case <-time.After(150 * time.Millisecond):
	}
}

// ended waits for the stream to end and returns its status code.
func (p *ps) ended(t *testing.T) codes.Code {
	t.Helper()
	select {
	case err := <-p.end:
		return code(err)
	case <-time.After(3 * time.Second):
		t.Fatal("the stream did not end")
	}
	return codes.Unknown
}

func TestCreateNeedsSession(t *testing.T) {
	f := newFix(t, nil)
	for _, tok := range []string{"", "garbage", "user:"} {
		_, err := f.c.CreateRoom(tctx(t, tok), &turnv1.CreateRoomRequest{})
		if code(err) != codes.Unauthenticated {
			t.Errorf("token %q: %v", tok, err)
		}
	}
	c := f.create("alice")
	if len(c.Room) != 32 || c.Peer != "host" || c.Token == "" || c.Expires != base.Add(time.Hour).Unix() {
		t.Fatalf("%+v", c)
	}
	if d := f.create("alice"); d.Room == c.Room || d.Token == c.Token {
		t.Fatal("two rooms alike")
	}
	if _, err := f.c.Credentials(tctx(t, ""), &turnv1.CredentialsRequest{}); code(err) != codes.Unauthenticated {
		t.Errorf("credentials without session: %v", err)
	}
	// two authorization headers are refused, not merged
	two := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer user:a", "authorization", "Bearer user:b"))
	if _, err := f.c.CreateRoom(two, &turnv1.CreateRoomRequest{}); code(err) != codes.Unauthenticated {
		t.Errorf("two authorization values: %v", err)
	}
}

func TestRoutingAndEvents(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	host := f.open(c.Room, c.Token)
	g1, g2 := f.join(c.Room), f.join(c.Room)
	if g1.Peer == g2.Peer || g1.Token == g2.Token || g1.Host != "host" {
		t.Fatalf("%+v %+v", g1, g2)
	}
	for _, g := range []*turnv1.JoinRoomResponse{g1, g2} {
		for _, kind := range []string{"sys.knock", "sys.join"} {
			if e := host.next(t); e.Kind != kind || e.From != g.Peer {
				t.Fatalf("%v, want %s from %s", e, kind, g.Peer)
			}
		}
	}
	s1, s2 := f.open(c.Room, g1.Token), f.open(c.Room, g2.Token)
	if e := s1.next(t); e.Kind != "sys.admitted" {
		t.Fatalf("%v", e)
	}
	s2.next(t)
	s1.send(g1.Peer, "host", "answer", []byte("sdp-1"))
	if e := host.next(t); e.Kind != "answer" || string(e.Body) != "sdp-1" || e.From != g1.Peer || e.To != "host" || e.Seq == 0 {
		t.Fatalf("%v", e)
	}
	host.send("host", g2.Peer, "offer", []byte("sdp-2"))
	if e := s2.next(t); e.Kind != "offer" || string(e.Body) != "sdp-2" || e.From != "host" {
		t.Fatalf("%v", e)
	}
	s1.nothing(t) // guest 1 never sees guest 2's message

	// the other peer's state is not the sender's fault: sys.error, stream stays open
	host.send("host", "g99", "x", nil)
	if e := host.next(t); e.Kind != "sys.error" || !strings.HasPrefix(string(e.Body), "NotFound: ") {
		t.Fatalf("%v", e)
	}
	host.send("host", "host", "x", nil)
	if e := host.next(t); e.Kind != "sys.error" {
		t.Fatalf("to self: %v", e)
	}
	host.send("host", g1.Peer, "offer", []byte("still open"))
	if e := s1.next(t); string(e.Body) != "still open" {
		t.Fatalf("%v", e)
	}
}

// Each protocol violation ends the sender's stream with its status. A fresh
// guest is used for each, since a violation is a departure.
func TestProtocolViolationsEndTheStream(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	for name, tc := range []struct {
		name         string
		from, to, kd string
		want         codes.Code
	}{
		{"spoofed from", "host", "host", "x", codes.PermissionDenied},
		{"guest to guest", "SELF", "g1", "x", codes.PermissionDenied},
		{"system kind", "SELF", "host", "sys.join", codes.InvalidArgument},
		{"empty kind", "SELF", "host", "", codes.InvalidArgument},
		{"upper-case kind", "SELF", "host", "Offer", codes.InvalidArgument},
		{"long kind", "SELF", "host", strings.Repeat("a", 33), codes.InvalidArgument},
	} {
		_ = name
		g := f.join(c.Room)
		s := f.open(c.Room, g.Token)
		s.next(t) // sys.admitted
		from := tc.from
		if from == "SELF" {
			from = g.Peer
		}
		s.send(from, tc.to, tc.kd, nil)
		if got := s.ended(t); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
		// the violation was a departure: the token is dead
		if _, err := f.c.RoomCredentials(tctx(t, g.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.Unauthenticated {
			t.Errorf("%s: the token of a guest that broke the protocol still works: %v", tc.name, err)
		}
	}
}

func TestStreamAuth(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	g := f.join(c.Room)
	for name, tc := range map[string]struct {
		room, token string
		want        codes.Code
	}{
		"no token":      {c.Room, "", codes.Unauthenticated},
		"session token": {c.Room, "user:alice", codes.Unauthenticated},
		"wrong room":    {strings.Repeat("0", 32), c.Token, codes.NotFound},
		"malformed":     {"zz", c.Token, codes.NotFound},
		"no room":       {"", c.Token, codes.NotFound},
	} {
		if got := f.open(tc.room, tc.token).ended(t); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
	// control: the right pair opens
	f.open(c.Room, g.Token).next(t)
	// a guest's token with another room's ID
	other := f.create("bob")
	if got := f.open(other.Room, g.Token).ended(t); got != codes.Unauthenticated {
		t.Errorf("token of one room on another: %v", got)
	}
}

func TestSecondStreamRefused(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	host := f.open(c.Room, c.Token)
	f.join(c.Room)
	host.next(t)
	if got := f.open(c.Room, c.Token).ended(t); got != codes.AlreadyExists {
		t.Fatalf("second stream: %v", got)
	}
}

func TestBoundMessageSize(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxMessageBytes = 100 })
	c := f.create("alice")
	host := f.open(c.Room, c.Token)
	g := f.join(c.Room)
	s := f.open(c.Room, g.Token)
	s.next(t)
	host.next(t)
	host.next(t)
	s.send(g.Peer, "host", "answer", []byte(strings.Repeat("a", 100)))
	if e := host.next(t); len(e.Body) != 100 {
		t.Fatalf("at the bound: %d bytes", len(e.Body))
	}
	s.send(g.Peer, "host", "answer", []byte(strings.Repeat("a", 101)))
	if got := s.ended(t); got != codes.ResourceExhausted {
		t.Fatalf("one over: %v", got)
	}
	// far over: refused by gRPC's own receive bound, before the service sees it
	g2 := f.join(c.Room)
	s2 := f.open(c.Room, g2.Token)
	s2.next(t)
	s2.send(g2.Peer, "host", "answer", []byte(strings.Repeat("a", 1<<20)))
	if got := s2.ended(t); got != codes.ResourceExhausted {
		t.Fatalf("1 MiB: %v", got)
	}
}

func TestBoundQueue(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxQueue = 4 })
	c := f.create("alice")
	g := f.join(c.Room) // the host's queue already holds sys.knock and sys.join: 2 of 4
	s := f.open(c.Room, g.Token)
	s.next(t)
	for range 4 { // two fit, two are refused
		s.send(g.Peer, "host", "ice", nil)
	}
	for range 2 {
		if e := s.next(t); e.Kind != "sys.error" || !strings.HasPrefix(string(e.Body), "ResourceExhausted: ") {
			t.Fatalf("%v", e)
		}
	}
	s.nothing(t)
	// draining makes room again (control)
	host := f.open(c.Room, c.Token)
	for range 4 {
		host.next(t)
	}
	host.nothing(t)
	s.send(g.Peer, "host", "ice", nil)
	if e := host.next(t); e.Kind != "ice" {
		t.Fatalf("after drain: %v", e)
	}
}

func TestBoundGuests(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxGuests = 2 })
	c := f.create("alice")
	f.join(c.Room)
	f.join(c.Room)
	third := f.knock(c.Room, "") // knocking is allowed; being admitted is what the cap counts
	if err := f.decide("admit", c.Room, third.Peer); code(err) != codes.ResourceExhausted {
		t.Fatalf("third admitted guest: %v", err)
	}
	if err := f.decide("deny", c.Room, third.Peer); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if _, err := f.c.JoinRoom(tctx(t, ""), &turnv1.JoinRoomRequest{Room: strings.Repeat("a", 32)}); code(err) != codes.NotFound {
		t.Fatalf("unknown room: %v", err)
	}
}

func TestBoundRoomsPerSubjectAndGlobal(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxRoomsPerSubject = 2; c.Limits.MaxRooms = 3 })
	f.create("alice")
	r2 := f.create("alice")
	if _, err := f.c.CreateRoom(tctx(t, "user:alice"), &turnv1.CreateRoomRequest{}); code(err) != codes.ResourceExhausted {
		t.Fatalf("third room of one subject: %v", err)
	}
	f.create("bob") // another subject is not charged to alice
	if _, err := f.c.CreateRoom(tctx(t, "user:carol"), &turnv1.CreateRoomRequest{}); code(err) != codes.Unavailable {
		t.Fatalf("global cap: %v", err)
	}
	// closing a room frees its slot
	if _, err := f.c.CloseRoom(tctx(t, r2.Token), &turnv1.RoomRef{Room: r2.Room}); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := f.c.CreateRoom(tctx(t, "user:alice"), &turnv1.CreateRoomRequest{}); err != nil {
		t.Fatalf("after close: %v", err)
	}
}

func TestRoomTTL(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.RoomTTL = 10 * time.Minute })
	c := f.create("alice")
	g := f.join(c.Room)
	s := f.open(c.Room, g.Token)
	s.next(t)
	f.off.Store(599)
	if _, err := f.c.RoomCredentials(tctx(t, g.Token), &turnv1.RoomRef{Room: c.Room}); err != nil {
		t.Fatalf("just before: %v", err)
	}
	f.off.Store(600)
	f.s.Sweep()
	if e := s.next(t); e.Kind != "sys.closed" {
		t.Fatalf("%v", e)
	}
	if got := s.ended(t); got != codes.OK {
		t.Fatalf("the stream ends cleanly after sys.closed: %v", got)
	}
	if _, err := f.c.JoinRoom(tctx(t, ""), &turnv1.JoinRoomRequest{Room: c.Room}); code(err) != codes.NotFound {
		t.Fatalf("join after TTL: %v", err)
	}
	if _, err := f.c.RoomCredentials(tctx(t, g.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.NotFound {
		t.Fatalf("credentials after TTL: %v", err)
	}
	if f.s.Rooms() != 0 {
		t.Fatalf("rooms %d", f.s.Rooms())
	}
}

func TestLazyExpiryFreesQuota(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.RoomTTL = time.Minute; c.Limits.MaxRoomsPerSubject = 1 })
	f.create("alice")
	if _, err := f.c.CreateRoom(tctx(t, "user:alice"), &turnv1.CreateRoomRequest{}); code(err) != codes.ResourceExhausted {
		t.Fatalf("%v", err)
	}
	f.off.Store(61)
	f.create("alice")
}

func TestCredentials(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxCredsPerRoom = 2; c.Limits.RoomTTL = 30 * time.Minute })
	r, err := f.c.Credentials(tctx(t, "user:alice"), &turnv1.CredentialsRequest{})
	if err != nil || r.Ttl != 3600 || len(r.IceServers) != 2 {
		t.Fatalf("%v %v", r, err)
	}
	turn := r.IceServers[1]
	if pw, ok := f.ring.Verify(turn.Username, f.now()); !ok || pw != turn.Credential {
		t.Fatalf("host creds do not verify: %v", turn)
	}
	// guest credentials: charged to the host's subject, expiring with the room
	c := f.create("alice")
	g := f.join(c.Room)
	r, err = f.c.RoomCredentials(tctx(t, g.Token), &turnv1.RoomRef{Room: c.Room})
	if err != nil {
		t.Fatal(err)
	}
	if r.Ttl != 1800 {
		t.Fatalf("guest ttl %d, want the room's remaining 1800", r.Ttl)
	}
	turn = r.IceServers[1]
	exp, subj, _ := creds.Parse(turn.Username)
	if exp.Unix() != c.Expires || !strings.HasSuffix(subj, ".alice") {
		t.Fatalf("username %q (room expires %d)", turn.Username, c.Expires)
	}
	if _, ok := f.ring.Verify(turn.Username, f.now()); !ok {
		t.Fatal("guest creds do not verify")
	}
	if _, ok := f.ring.Verify(turn.Username, f.now().Add(31*time.Minute)); ok {
		t.Fatal("guest creds outlive the room")
	}
	f.off.Store(600)
	r, _ = f.c.RoomCredentials(tctx(t, c.Token), &turnv1.RoomRef{Room: c.Room})
	if r.Ttl != 1200 {
		t.Fatalf("ttl %d", r.Ttl)
	}
	if _, err := f.c.RoomCredentials(tctx(t, g.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.ResourceExhausted {
		t.Fatalf("over the per-room cap: %v", err)
	}
	if _, err := f.c.RoomCredentials(tctx(t, ""), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.Unauthenticated {
		t.Fatalf("no token: %v", err)
	}
}

func TestLeaveByEndingTheStream(t *testing.T) {
	// HostGrace < 0 is the behaviour before the grace period existed.
	f := newFix(t, func(c *Config) { c.Limits.HostGrace = -1 })
	c := f.create("alice")
	g := f.join(c.Room)
	host := f.open(c.Room, c.Token)
	host.next(t) // sys.knock
	host.next(t) // sys.join
	gs := f.open(c.Room, g.Token)
	gs.next(t)
	// a guest cannot close the room
	if _, err := f.c.CloseRoom(tctx(t, g.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.PermissionDenied {
		t.Fatalf("guest closing the room: %v", err)
	}
	if err := gs.st.CloseSend(); err != nil { // half-close: leaving
		t.Fatal(err)
	}
	if e := host.next(t); e.Kind != "sys.leave" || e.From != g.Peer {
		t.Fatalf("%v", e)
	}
	if _, err := f.c.RoomCredentials(tctx(t, g.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.Unauthenticated {
		t.Fatalf("a guest that left still has a token: %v", err)
	}
	// the host's stream ending closes the room
	g2 := f.join(c.Room)
	g2s := f.open(c.Room, g2.Token)
	g2s.next(t)
	host.next(t)
	host.next(t)
	_ = host.st.CloseSend()
	if e := g2s.next(t); e.Kind != "sys.closed" {
		t.Fatalf("%v", e)
	}
	if f.s.Rooms() != 0 {
		t.Fatal("the room outlived its host's stream")
	}
}

func TestCloseRoom(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	g := f.join(c.Room)
	s := f.open(c.Room, g.Token)
	s.next(t)
	if _, err := f.c.CloseRoom(tctx(t, c.Token), &turnv1.RoomRef{Room: c.Room}); err != nil {
		t.Fatal(err)
	}
	if e := s.next(t); e.Kind != "sys.closed" {
		t.Fatalf("%v", e)
	}
}

func TestNewRefusals(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty config")
	}
}

func TestRun(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.RoomTTL = time.Minute })
	f.create("alice")
	f.off.Store(120)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.s.Run(ctx, 10*time.Millisecond); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for f.s.Rooms() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if f.s.Rooms() != 0 {
		t.Fatal("janitor did not sweep")
	}
}
