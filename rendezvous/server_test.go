package rendezvous

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-turn/turn/creds"
)

var base = time.Unix(1_800_000_000, 0)

type fix struct {
	t    *testing.T
	s    *Server
	ts   *httptest.Server
	ring *creds.Keyring
	off  atomic.Int64 // seconds the clock has advanced
}

func (f *fix) now() time.Time { return base.Add(time.Duration(f.off.Load()) * time.Second) }

func newFix(t *testing.T, mod func(*Config)) *fix {
	t.Helper()
	f := &fix{t: t}
	f.ring, _ = creds.NewKeyring([]byte("0123456789abcdef0123"))
	cfg := Config{
		Auth: func(r *http.Request) (string, error) {
			if tok := bearerToken(r); strings.HasPrefix(tok, "user:") {
				return tok[5:], nil
			}
			return "", errors.New("no")
		},
		Keyring: f.ring, STUN: []string{"stun:t.example:3478"}, TURN: []string{"turn:t.example:3478?transport=udp"},
		Origins: []string{"https://go-tex.github.io"}, Now: f.now,
	}
	if mod != nil {
		mod(&cfg)
	}
	var err error
	if f.s, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	f.ts = httptest.NewServer(f.s.Handler())
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fix) req(method, path, token string, body any, hdr ...string) (*http.Response, []byte) {
	f.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	r, _ := http.NewRequest(method, f.ts.URL+path, rd)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (f *fix) create(user string) CreateResponse {
	f.t.Helper()
	resp, b := f.req("POST", "/rooms", "user:"+user, nil)
	if resp.StatusCode != 201 {
		f.t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	var c CreateResponse
	_ = json.Unmarshal(b, &c)
	return c
}

func (f *fix) join(room string) JoinResponse {
	f.t.Helper()
	resp, b := f.req("POST", "/rooms/"+room+"/join", "", nil)
	if resp.StatusCode != 201 {
		f.t.Fatalf("join: %d %s", resp.StatusCode, b)
	}
	var j JoinResponse
	_ = json.Unmarshal(b, &j)
	return j
}

func (f *fix) send(room, token string, m MessageRequest) int {
	f.t.Helper()
	resp, _ := f.req("POST", "/rooms/"+room+"/messages", token, m)
	return resp.StatusCode
}

// stream opens the SSE stream and returns a channel of events ("closed" is Kind "closed").
func (f *fix) stream(room, token string) (<-chan Event, *http.Response) {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f.t.Cleanup(cancel)
	r, _ := http.NewRequestWithContext(ctx, "GET", f.ts.URL+"/rooms/"+room+"/events", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	ch := make(chan Event, 256)
	if resp.StatusCode != 200 {
		close(ch)
		return ch, resp
	}
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(resp.Body)
		ev := ""
		for sc.Scan() {
			switch l := sc.Text(); {
			case strings.HasPrefix(l, "event: "):
				ev = l[7:]
			case strings.HasPrefix(l, "data: "):
				var e Event
				_ = json.Unmarshal([]byte(l[6:]), &e)
				if ev == "closed" {
					e.Kind = "closed"
				}
				ch <- e
			}
		}
	}()
	return ch, resp
}

func next(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("stream ended")
		}
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("no event")
	}
	return Event{}
}

func TestCreateNeedsSession(t *testing.T) {
	f := newFix(t, nil)
	for _, tok := range []string{"", "garbage", "user:"} {
		if resp, _ := f.req("POST", "/rooms", tok, nil); resp.StatusCode != 401 {
			t.Errorf("token %q: %d", tok, resp.StatusCode)
		}
	}
	c := f.create("alice")
	if len(c.Room) != 32 || c.Peer != "host" || c.Token == "" || c.Expires != base.Add(time.Hour).Unix() {
		t.Fatalf("%+v", c)
	}
	if d := f.create("alice"); d.Room == c.Room || d.Token == c.Token {
		t.Fatal("two rooms alike")
	}
	if resp, _ := f.req("POST", "/credentials", "", nil); resp.StatusCode != 401 {
		t.Errorf("credentials without session: %d", resp.StatusCode)
	}
}

func TestRoutingAndEvents(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	hostEv, _ := f.stream(c.Room, c.Token)
	g1, g2 := f.join(c.Room), f.join(c.Room)
	if g1.Peer == g2.Peer || g1.Token == g2.Token || g1.Host != "host" {
		t.Fatalf("%+v %+v", g1, g2)
	}
	if e := next(t, hostEv); e.Kind != "sys.join" || e.From != g1.Peer {
		t.Fatalf("%+v", e)
	}
	if e := next(t, hostEv); e.Kind != "sys.join" || e.From != g2.Peer {
		t.Fatalf("%+v", e)
	}
	g1Ev, _ := f.stream(c.Room, g1.Token)
	g2Ev, _ := f.stream(c.Room, g2.Token)
	// guest to host
	if st := f.send(c.Room, g1.Token, MessageRequest{From: g1.Peer, To: "host", Kind: "answer", Body: "sdp-1"}); st != 204 {
		t.Fatalf("guest->host %d", st)
	}
	if e := next(t, hostEv); e.Kind != "answer" || e.Body != "sdp-1" || e.From != g1.Peer || e.To != "host" {
		t.Fatalf("%+v", e)
	}
	// host to one guest only
	if st := f.send(c.Room, c.Token, MessageRequest{From: "host", To: g2.Peer, Kind: "offer", Body: "sdp-2"}); st != 204 {
		t.Fatalf("host->guest %d", st)
	}
	if e := next(t, g2Ev); e.Kind != "offer" || e.Body != "sdp-2" {
		t.Fatalf("%+v", e)
	}
	select {
	case e := <-g1Ev:
		t.Fatalf("guest 1 got guest 2's message: %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
	// refusals
	for name, tc := range map[string]struct {
		tok string
		m   MessageRequest
		st  int
	}{
		"spoofed from":               {g1.Token, MessageRequest{From: "host", To: "host", Kind: "x"}, 403},
		"guest to guest":             {g1.Token, MessageRequest{From: g1.Peer, To: g2.Peer, Kind: "x"}, 403},
		"to nobody":                  {c.Token, MessageRequest{From: "host", To: "g99", Kind: "x"}, 404},
		"to self":                    {c.Token, MessageRequest{From: "host", To: "host", Kind: "x"}, 404},
		"system kind":                {g1.Token, MessageRequest{From: g1.Peer, To: "host", Kind: "sys.join"}, 400},
		"empty kind":                 {g1.Token, MessageRequest{From: g1.Peer, To: "host", Kind: ""}, 400},
		"upper kind":                 {g1.Token, MessageRequest{From: g1.Peer, To: "host", Kind: "Offer"}, 400},
		"no token":                   {"", MessageRequest{From: g1.Peer, To: "host", Kind: "x"}, 401},
		"another token":              {"user:alice", MessageRequest{From: "host", To: g1.Peer, Kind: "x"}, 401},
		"guest 1's token as guest 2": {g1.Token, MessageRequest{From: g2.Peer, To: "host", Kind: "x"}, 403},
	} {
		if st := f.send(c.Room, tc.tok, tc.m); st != tc.st {
			t.Errorf("%s: %d, want %d", name, st, tc.st)
		}
	}
	// the room ID alone is a capability to JOIN, not to read or write.
	if resp, _ := f.req("GET", "/rooms/"+c.Room+"/events", "", nil); resp.StatusCode != 401 {
		t.Errorf("events without token: %d", resp.StatusCode)
	}
	if resp, _ := f.req("GET", "/rooms/"+strings.Repeat("0", 32)+"/events", c.Token, nil); resp.StatusCode != 404 {
		t.Errorf("unknown room: %d", resp.StatusCode)
	}
	if resp, _ := f.req("GET", "/rooms/zz/events", c.Token, nil); resp.StatusCode != 404 {
		t.Errorf("malformed room id: %d", resp.StatusCode)
	}
	if resp, _ := f.req("POST", "/rooms/"+c.Room+"/messages", c.Token, `{"from":"host","to":"`+g1.Peer+`","kind":"x","extra":1}`); resp.StatusCode != 400 {
		t.Errorf("unknown field: %d", resp.StatusCode)
	}
	if st := f.send(c.Room, c.Token, MessageRequest{From: "host", To: g1.Peer, Kind: "offer", Body: "ok"}); st != 204 {
		t.Errorf("control: %d", st)
	}
}

func TestSecondStreamRefused(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	ev, _ := f.stream(c.Room, c.Token)
	f.join(c.Room)
	next(t, ev)
	if _, resp := f.stream(c.Room, c.Token); resp.StatusCode != 409 {
		t.Fatalf("second stream: %d", resp.StatusCode)
	}
}

func TestBoundMessageSize(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxMessageBytes = 100 })
	c := f.create("alice")
	g := f.join(c.Room)
	ok := MessageRequest{From: g.Peer, To: "host", Kind: "answer", Body: strings.Repeat("a", 100)}
	if st := f.send(c.Room, g.Token, ok); st != 204 {
		t.Fatalf("at the bound: %d", st)
	}
	ok.Body += "a"
	if st := f.send(c.Room, g.Token, ok); st != 413 {
		t.Fatalf("one over: %d", st)
	}
	// far over: refused by the reader, not buffered
	big := MessageRequest{From: g.Peer, To: "host", Kind: "answer", Body: strings.Repeat("a", 1<<20)}
	if st := f.send(c.Room, g.Token, big); st != 413 {
		t.Fatalf("1 MiB: %d", st)
	}
}

func TestBoundQueue(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxQueue = 3 })
	c := f.create("alice")
	g := f.join(c.Room) // the host's queue already holds sys.join: 1 of 3
	m := MessageRequest{From: g.Peer, To: "host", Kind: "ice"}
	for i := 0; i < 2; i++ {
		if st := f.send(c.Room, g.Token, m); st != 204 {
			t.Fatalf("message %d: %d", i, st)
		}
	}
	// 1 sys.join + 2 messages = 3: full.
	if st := f.send(c.Room, g.Token, m); st != 429 {
		t.Fatalf("over the queue bound: %d", st)
	}
	// draining makes room again (control)
	ev, _ := f.stream(c.Room, c.Token)
	for i := 0; i < 3; i++ {
		next(t, ev)
	}
	time.Sleep(50 * time.Millisecond)
	if st := f.send(c.Room, g.Token, m); st != 204 {
		t.Fatalf("after drain: %d", st)
	}
}

func TestBoundGuests(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxGuests = 2 })
	c := f.create("alice")
	f.join(c.Room)
	f.join(c.Room)
	if resp, _ := f.req("POST", "/rooms/"+c.Room+"/join", "", nil); resp.StatusCode != 429 {
		t.Fatalf("third guest: %d", resp.StatusCode)
	}
	if resp, _ := f.req("POST", "/rooms/"+strings.Repeat("a", 32)+"/join", "", nil); resp.StatusCode != 404 {
		t.Fatalf("unknown room: %d", resp.StatusCode)
	}
}

func TestBoundRoomsPerSubjectAndGlobal(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxRoomsPerSubject = 2; c.Limits.MaxRooms = 3 })
	f.create("alice")
	r2 := f.create("alice")
	if resp, _ := f.req("POST", "/rooms", "user:alice", nil); resp.StatusCode != 429 {
		t.Fatalf("third room of one subject: %d", resp.StatusCode)
	}
	f.create("bob") // another subject is not charged to alice
	if resp, _ := f.req("POST", "/rooms", "user:carol", nil); resp.StatusCode != 503 {
		t.Fatalf("global cap: %d", resp.StatusCode)
	}
	// closing a room frees its slot
	if resp, _ := f.req("DELETE", "/rooms/"+r2.Room, r2.Token, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp, _ := f.req("POST", "/rooms", "user:alice", nil); resp.StatusCode != 201 {
		t.Fatalf("after delete: %d", resp.StatusCode)
	}
}

func TestRoomTTL(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.RoomTTL = 10 * time.Minute })
	c := f.create("alice")
	g := f.join(c.Room)
	ev, _ := f.stream(c.Room, g.Token)
	f.off.Store(599)
	if st := f.send(c.Room, g.Token, MessageRequest{From: g.Peer, To: "host", Kind: "x"}); st != 204 {
		t.Fatalf("just before: %d", st)
	}
	f.off.Store(600)
	f.s.Sweep()
	if e := next(t, ev); e.Kind != "closed" {
		t.Fatalf("%+v", e)
	}
	if resp, _ := f.req("POST", "/rooms/"+c.Room+"/join", "", nil); resp.StatusCode != 404 {
		t.Fatalf("join after TTL: %d", resp.StatusCode)
	}
	if st := f.send(c.Room, g.Token, MessageRequest{From: g.Peer, To: "host", Kind: "x"}); st != 404 {
		t.Fatalf("send after TTL: %d", st)
	}
	if f.s.Rooms() != 0 {
		t.Fatalf("rooms %d", f.s.Rooms())
	}
}

func TestLazyExpiryFreesQuota(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.RoomTTL = time.Minute; c.Limits.MaxRoomsPerSubject = 1 })
	f.create("alice")
	if resp, _ := f.req("POST", "/rooms", "user:alice", nil); resp.StatusCode != 429 {
		t.Fatalf("%d", resp.StatusCode)
	}
	f.off.Store(61)
	f.create("alice")
}

func TestCredentials(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxCredsPerRoom = 2; c.Limits.RoomTTL = 30 * time.Minute })
	// host credentials
	resp, b := f.req("POST", "/credentials", "user:alice", nil)
	var r creds.Response
	if resp.StatusCode != 200 || json.Unmarshal(b, &r) != nil || r.TTL != 3600 || len(r.ICEServers) != 2 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	turn := r.ICEServers[1]
	if pw, ok := f.ring.Verify(turn.Username, f.now()); !ok || pw != turn.Credential {
		t.Fatalf("host creds do not verify: %+v", turn)
	}
	// guest credentials: charged to the host's subject, expiring with the room
	c := f.create("alice")
	g := f.join(c.Room)
	resp, b = f.req("POST", "/rooms/"+c.Room+"/credentials", g.Token, nil)
	if resp.StatusCode != 200 || json.Unmarshal(b, &r) != nil {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if r.TTL != 1800 {
		t.Fatalf("guest ttl %d, want the room's remaining 1800", r.TTL)
	}
	turn = r.ICEServers[1]
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
	// later in the room's life the TTL shrinks
	f.off.Store(600)
	_, b = f.req("POST", "/rooms/"+c.Room+"/credentials", c.Token, nil)
	_ = json.Unmarshal(b, &r)
	if r.TTL != 1200 {
		t.Fatalf("ttl %d", r.TTL)
	}
	// cap and auth
	if resp, _ := f.req("POST", "/rooms/"+c.Room+"/credentials", g.Token, nil); resp.StatusCode != 429 {
		t.Fatalf("over the per-room cap: %d", resp.StatusCode)
	}
	if resp, _ := f.req("POST", "/rooms/"+c.Room+"/credentials", "", nil); resp.StatusCode != 401 {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
}

func TestCORS(t *testing.T) {
	f := newFix(t, nil)
	resp, _ := f.req("POST", "/rooms", "user:a", nil, "Origin", "https://go-tex.github.io")
	if resp.StatusCode != 201 || resp.Header.Get("Access-Control-Allow-Origin") != "https://go-tex.github.io" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	if resp.Header.Get("Vary") != "Origin" {
		t.Errorf("Vary %q", resp.Header.Get("Vary"))
	}
	pre, _ := f.req("OPTIONS", "/rooms", "", nil, "Origin", "https://go-tex.github.io", "Access-Control-Request-Method", "POST")
	if pre.StatusCode != 204 || !strings.Contains(pre.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight %d %v", pre.StatusCode, pre.Header)
	}
	for _, o := range []string{"https://evil.example", "https://go-tex.github.io.evil.example", "https://GO-TEX.github.io", "null", "*", "http://go-tex.github.io"} {
		resp, _ := f.req("POST", "/rooms", "user:a", nil, "Origin", o)
		if resp.StatusCode != 403 || resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("origin %q: %d %q", o, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
		}
		pre, _ := f.req("OPTIONS", "/rooms", "", nil, "Origin", o, "Access-Control-Request-Method", "POST")
		if pre.StatusCode != 403 || pre.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("preflight origin %q: %d", o, pre.StatusCode)
		}
	}
	if _, err := New(Config{Auth: func(*http.Request) (string, error) { return "", nil }, Keyring: f.ring, Origins: []string{"*"}}); err == nil {
		t.Error("wildcard origin accepted")
	}
}

func TestLeaveAndDelete(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	g := f.join(c.Room)
	ev, _ := f.stream(c.Room, c.Token)
	next(t, ev) // sys.join
	if resp, _ := f.req("DELETE", "/rooms/"+c.Room, g.Token, nil); resp.StatusCode != 403 {
		t.Fatalf("guest closing the room: %d", resp.StatusCode)
	}
	if resp, _ := f.req("POST", "/rooms/"+c.Room+"/leave", g.Token, nil); resp.StatusCode != 204 {
		t.Fatalf("leave: %d", resp.StatusCode)
	}
	if e := next(t, ev); e.Kind != "sys.leave" || e.From != g.Peer {
		t.Fatalf("%+v", e)
	}
	if st := f.send(c.Room, g.Token, MessageRequest{From: g.Peer, To: "host", Kind: "x"}); st != 401 {
		t.Fatalf("a guest that left can still send: %d", st)
	}
	if resp, _ := f.req("DELETE", "/rooms/"+c.Room, c.Token, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if e := next(t, ev); e.Kind != "closed" {
		t.Fatalf("%+v", e)
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
