package rendezvous

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-turn/turn/creds"
	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	"google.golang.org/grpc/codes"
)

// A room of a host and guests that are admitted and streaming.
type crowd struct {
	hid   string // the creator's peer ID
	f     *fix
	room  string
	htok  string
	host  *ps
	guest map[string]*turnv1.JoinRoomResponse // by peer ID
	gs    map[string]*ps
	order []string // peer IDs in ADMISSION order
}

// newCrowd opens a room for alice and admits the guests named in order: the
// knocks come in that order too unless knockOrder says otherwise.
func newCrowd(t *testing.T, f *fix, n int) *crowd {
	t.Helper()
	c := f.create("alice")
	cr := &crowd{hid: c.Peer, f: f, room: c.Room, htok: c.Token, guest: map[string]*turnv1.JoinRoomResponse{}, gs: map[string]*ps{}}
	cr.host = f.open(c.Room, c.Token)
	for i := 0; i < n; i++ {
		cr.add(t, "guest")
	}
	return cr
}

// add knocks, is admitted by the CURRENT host and opens its stream.
func (cr *crowd) add(t *testing.T, name string) *turnv1.JoinRoomResponse {
	t.Helper()
	g := cr.f.knock(cr.room, name)
	if err := cr.f.decideAs("admit", cr.room, cr.htok, g.Peer); err != nil {
		t.Fatalf("admit %s: %v", g.Peer, err)
	}
	cr.guest[g.Peer] = g
	cr.order = append(cr.order, g.Peer)
	cr.gs[g.Peer] = cr.f.open(cr.room, g.Token)
	return g
}

// waitFor reads p's events until one is of kind, and returns it.
func (p *ps) waitFor(t *testing.T, kind string) *turnv1.Envelope {
	t.Helper()
	for {
		e := p.next(t)
		if e.Kind == kind {
			return e
		}
	}
}

// kinds reads what p receives within d.
func (p *ps) within(d time.Duration) []*turnv1.Envelope {
	var out []*turnv1.Envelope
	end := time.After(d)
	for {
		select {
		case e, ok := <-p.ev:
			if !ok {
				return out
			}
			out = append(out, e)
		case <-end:
			return out
		}
	}
}

func hostChanged(t *testing.T, e *turnv1.Envelope) (from, to string) {
	t.Helper()
	var h hostChange
	if err := json.Unmarshal(e.Body, &h); err != nil {
		t.Fatalf("body %q: %v", e.Body, err)
	}
	return h.From, h.To
}

// hostLost waits until the server has seen the host's stream end.
func (f *fix) hostLost(room string) {
	f.t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		f.s.mu.Lock()
		rm := f.s.rooms[room]
		gone := rm != nil && !rm.hostGone.IsZero()
		f.s.mu.Unlock()
		if gone {
			return
		}
	}
	f.t.Fatal("the server never saw the host's stream end")
}

func (f *fix) hostOf(room string) string {
	f.s.mu.Lock()
	defer f.s.mu.Unlock()
	rm := f.s.rooms[room]
	if rm == nil {
		return ""
	}
	return rm.host.id
}

func (f *fix) advance(sec int64) { f.off.Add(sec) }

func (f *fix) reclaim(room, user string) (*turnv1.ReclaimResponse, error) {
	return f.c.Reclaim(tctx(f.t, "user:"+user), &turnv1.ReclaimRequest{Room: room})
}

func (f *fix) handOver(room, token, to string) error {
	_, err := f.c.HandOver(tctx(f.t, token), &turnv1.HandOverRequest{Room: room, To: to})
	return err
}

func TestHostBackWithinGraceKeepsTheRole(t *testing.T) {
	ev := &events{}
	f := newFix(t, func(c *Config) { c.Observer = ev })
	cr := newCrowd(t, f, 2)
	g1, g2 := cr.order[0], cr.order[1]
	_ = cr.host.st.CloseSend()
	f.hostLost(cr.room)
	if f.s.Rooms() != 1 {
		t.Fatal("the room died with its host's stream")
	}
	// a guest writes to the host while it is away: queued for it
	cr.gs[g1].send(g1, "host", "offer", []byte("while-away"))
	f.advance(60)
	f.s.Sweep()
	if h := f.hostOf(cr.room); h != cr.hid {
		t.Fatalf("host %q before the grace is over", h)
	}
	// control: nobody is promoted before the end of the grace period
	for _, g := range []string{g1, g2} {
		for _, e := range cr.gs[g].within(50 * time.Millisecond) {
			if e.Kind == "sys.host-changed" {
				t.Fatalf("%s told of a handover within the grace: %v", g, e)
			}
		}
	}
	r, err := f.reclaim(cr.room, "alice")
	if err != nil || !r.Host || r.Peer != cr.hid || r.HostPeer != cr.hid || r.Token == cr.htok {
		t.Fatalf("%+v %v", r, err)
	}
	// the old host token is dead, the new one is the host's
	if err := f.decideAs("deny", cr.room, cr.htok, g2); code(err) != codes.Unauthenticated {
		t.Fatalf("old host token: %v", err)
	}
	h2 := f.open(cr.room, r.Token)
	if e := h2.waitFor(t, "offer"); string(e.Body) != "while-away" || e.From != g1 {
		t.Fatalf("a message sent in the grace period was lost: %v", e)
	}
	// well past the grace: still the host, no promotion
	f.advance(600)
	f.s.Sweep()
	if h := f.hostOf(cr.room); h != cr.hid {
		t.Fatalf("host %q after the host came back", h)
	}
	if err := f.decideAs("deny", cr.room, r.Token, g2); err != nil {
		t.Fatalf("the returned host cannot decide: %v", err)
	}
	if got := ev.all(); !strings.Contains(got, "host_lost=ok") || !strings.Contains(got, "reclaim=ok") || strings.Contains(got, "promote=") {
		t.Fatalf("events %s", got)
	}
}

func TestHostStreamReopenedWithItsTokenWithinGrace(t *testing.T) {
	f := newFix(t, nil)
	cr := newCrowd(t, f, 1)
	_ = cr.host.st.CloseSend()
	f.hostLost(cr.room)
	h := f.open(cr.room, cr.htok) // a network blip: the same token, a new stream
	f.advance(600)
	f.s.Sweep()
	if f.hostOf(cr.room) != cr.hid || f.s.Rooms() != 1 {
		t.Fatal("a host whose stream came back lost the room")
	}
	_ = h
}

func TestPromotionPastGraceIsTheEarliestAdmittedGuest(t *testing.T) {
	ev := &events{}
	// the waiting guest must outlast the grace period (the default waits are alike)
	f := newFix(t, func(c *Config) { c.Observer = ev; c.Limits.PendingTTL = 30 * time.Minute })
	c := f.create("alice")
	host := f.open(c.Room, c.Token)
	// g1 knocks first but g2 is admitted first; g3 is admitted last; g4 waits
	k1 := f.knock(c.Room, "one")
	k2 := f.knock(c.Room, "two")
	k3 := f.knock(c.Room, "three")
	k4 := f.knock(c.Room, "four")
	for _, k := range []*turnv1.JoinRoomResponse{k2, k1, k3} {
		if err := f.decide("admit", c.Room, k.Peer); err != nil {
			t.Fatal(err)
		}
	}
	gs := map[string]*ps{}
	for _, k := range []*turnv1.JoinRoomResponse{k1, k2, k3, k4} {
		gs[k.Peer] = f.open(c.Room, k.Token)
	}
	_ = host.st.CloseSend()
	f.hostLost(c.Room)
	f.advance(119)
	f.s.Sweep()
	if f.hostOf(c.Room) != c.Peer {
		t.Fatal("promoted before the grace period ended")
	}
	f.advance(2)
	f.s.Sweep()
	if h := f.hostOf(c.Room); h != k2.Peer {
		t.Fatalf("host %q, want the earliest ADMITTED %q (not the first to knock, not the pending %q)", h, k2.Peer, k4.Peer)
	}
	// every peer, the promoted one and the pending one included, is told
	for id, p := range gs {
		from, to := hostChanged(t, p.waitFor(t, "sys.host-changed"))
		if from != c.Peer || to != k2.Peer {
			t.Fatalf("%s: %s -> %s", id, from, to)
		}
	}
	// the new host keeps its peer ID and token, and is told who is there: the
	// pending guest knocks again, the admitted ones join again
	var knocks, joins []string
	for _, e := range gs[k2.Peer].within(100 * time.Millisecond) {
		switch e.Kind {
		case "sys.knock":
			knocks = append(knocks, e.From)
		case "sys.join":
			joins = append(joins, e.From)
		}
	}
	if len(knocks) != 1 || knocks[0] != k4.Peer || len(joins) != 2 {
		t.Fatalf("re-announced: knocks %v joins %v", knocks, joins)
	}
	// host powers: admit the pending guest, mint credentials, then close
	if err := f.decideAs("admit", c.Room, k2.Token, k4.Peer); err != nil {
		t.Fatalf("the promoted host cannot admit: %v", err)
	}
	if _, err := f.c.RoomCredentials(tctx(t, k2.Token), &turnv1.RoomRef{Room: c.Room}); err != nil {
		t.Fatal(err)
	}
	// the old host's token is dead
	if err := f.decideAs("admit", c.Room, c.Token, k4.Peer); code(err) != codes.Unauthenticated {
		t.Fatalf("old host token: %v", err)
	}
	if _, err := f.c.CloseRoom(tctx(t, c.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.Unauthenticated {
		t.Fatalf("old host closing: %v", err)
	}
	// "host" still means the current host for a guest; a message routes to it
	gs[k1.Peer].send(k1.Peer, "host", "offer", []byte("hi"))
	if e := gs[k2.Peer].waitFor(t, "offer"); e.From != k1.Peer || e.To != k2.Peer || string(e.Body) != "hi" {
		t.Fatalf("%v", e)
	}
	gs[k2.Peer].send(k2.Peer, k3.Peer, "answer", []byte("yo"))
	if e := gs[k3.Peer].waitFor(t, "answer"); e.From != k2.Peer {
		t.Fatalf("%v", e)
	}
	// and the new host's leaving does not close the room either: next in line
	if _, err := f.c.CloseRoom(tctx(t, k2.Token), &turnv1.RoomRef{Room: c.Room}); err != nil {
		t.Fatalf("the promoted host cannot close: %v", err)
	}
	if got := ev.all(); !strings.Contains(got, "promote=ok") || strings.Contains(got, k2.Peer) {
		t.Fatalf("events %s", got)
	}
}

func TestPromotedHostLeavingPromotesTheNext(t *testing.T) {
	f := newFix(t, nil)
	cr := newCrowd(t, f, 3)
	g1, g2, g3 := cr.order[0], cr.order[1], cr.order[2]
	_ = cr.host.st.CloseSend()
	f.hostLost(cr.room)
	f.advance(121)
	f.s.Sweep()
	if f.hostOf(cr.room) != g1 {
		t.Fatalf("host %q", f.hostOf(cr.room))
	}
	// g1 dies in its turn: g2 is next, g3 after
	_ = cr.gs[g1].st.CloseSend()
	f.hostLost(cr.room)
	f.advance(121)
	f.s.Sweep()
	if f.hostOf(cr.room) != g2 {
		t.Fatalf("host %q, want %q", f.hostOf(cr.room), g2)
	}
	if e := cr.gs[g3].waitFor(t, "sys.host-changed"); e == nil {
		t.Fatal("no news")
	}
}

func TestNoCandidateClosesTheRoom(t *testing.T) {
	ev := &events{}
	f := newFix(t, func(c *Config) { c.Observer = ev })
	c := f.create("alice")
	host := f.open(c.Room, c.Token)
	pend := f.knock(c.Room, "waiting")
	ps := f.open(c.Room, pend.Token)
	_ = host.st.CloseSend()
	f.hostLost(c.Room)
	f.advance(121)
	f.s.Sweep()
	// the pending guest is NEVER promoted: nobody else was there, the room ends
	if f.s.Rooms() != 0 {
		t.Fatal("a pending guest kept the room alive (or was promoted)")
	}
	if e := ps.waitFor(t, "sys.closed"); e == nil {
		t.Fatal("no close")
	}
	if got := ev.all(); !strings.Contains(got, "promote=failed_precondition") {
		t.Fatalf("events %s", got)
	}
}

func TestDeniedAndDisconnectedGuestsAreSkipped(t *testing.T) {
	f := newFix(t, nil)
	cr := newCrowd(t, f, 3)
	g1, g2, g3 := cr.order[0], cr.order[1], cr.order[2]
	if err := f.decideAs("deny", cr.room, cr.htok, g1); err != nil { // removed: its token is dead
		t.Fatal(err)
	}
	_ = cr.gs[g2].st.CloseSend() // left
	cr.host.waitFor(t, "sys.leave")
	_ = cr.host.st.CloseSend()
	f.hostLost(cr.room)
	f.advance(121)
	f.s.Sweep()
	if h := f.hostOf(cr.room); h != g3 {
		t.Fatalf("host %q, want the only guest left (%q)", h, g3)
	}
}

func TestHandOverRefusals(t *testing.T) {
	f := newFix(t, nil)
	cr := newCrowd(t, f, 2)
	g1, g2 := cr.order[0], cr.order[1]
	pend := f.knock(cr.room, "waiting")
	f.open(cr.room, pend.Token)
	denied := f.knock(cr.room, "nope")
	if err := f.decide("deny", cr.room, denied.Peer); err != nil {
		t.Fatal(err)
	}
	stranger := f.create("carol")
	for name, tc := range map[string]struct {
		token, to string
		want      codes.Code
	}{
		"a guest promotes itself":        {cr.guest[g1].Token, g1, codes.PermissionDenied},
		"a guest promotes another":       {cr.guest[g1].Token, g2, codes.PermissionDenied},
		"a pending guest hands over":     {pend.Token, g1, codes.PermissionDenied},
		"to a pending guest":             {cr.htok, pend.Peer, codes.FailedPrecondition},
		"to a denied guest":              {cr.htok, denied.Peer, codes.NotFound},
		"to the host itself":             {cr.htok, "host", codes.InvalidArgument},
		"to nobody":                      {cr.htok, "g99", codes.NotFound},
		"to nothing":                     {cr.htok, "", codes.InvalidArgument},
		"with another room's host token": {stranger.Token, g1, codes.Unauthenticated},
		"with no token":                  {"", g1, codes.Unauthenticated},
		"with a made-up token":           {"deadbeef", g1, codes.Unauthenticated},
	} {
		if err := f.handOver(cr.room, tc.token, tc.to); code(err) != tc.want {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if h := f.hostOf(cr.room); h != cr.hid {
		t.Fatalf("a refused hand over moved the role to %q", h)
	}
	// control: the same call, made right, works
	if err := f.handOver(cr.room, cr.htok, g1); err != nil {
		t.Fatal(err)
	}
	if h := f.hostOf(cr.room); h != g1 {
		t.Fatalf("host %q", h)
	}
	// and now the OLD host cannot do it again
	if err := f.handOver(cr.room, cr.htok, g2); code(err) != codes.Unauthenticated {
		t.Fatalf("old host: %v", err)
	}
}

func TestHandOverToAGuestThatIsNotConnected(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	f.open(c.Room, c.Token)
	g := f.join(c.Room) // admitted, never opened its stream
	if err := f.handOver(c.Room, c.Token, g.Peer); code(err) != codes.FailedPrecondition {
		t.Fatalf("%v", err)
	}
}

func TestExplicitHandOverThenTheOldHostReturnsAsAGuest(t *testing.T) {
	ev := &events{}
	f := newFix(t, func(c *Config) { c.Observer = ev })
	cr := newCrowd(t, f, 2)
	g1, g2 := cr.order[0], cr.order[1]
	if err := f.handOver(cr.room, cr.htok, g2); err != nil { // not the earliest: the host chose
		t.Fatal(err)
	}
	// the old host is told, then its stream ends
	from, to := hostChanged(t, cr.host.waitFor(t, "sys.host-changed"))
	if from != cr.hid || to != g2 {
		t.Fatalf("%s -> %s", from, to)
	}
	select {
	case <-cr.host.end:
	case <-time.After(3 * time.Second):
		t.Fatal("the old host's stream is still open")
	}
	// a stranger cannot take its place; the person can come back, as a guest
	if _, err := f.reclaim(cr.room, "mallory"); code(err) != codes.PermissionDenied {
		t.Fatalf("stranger: %v", err)
	}
	if _, err := f.c.Reclaim(tctx(t, ""), &turnv1.ReclaimRequest{Room: cr.room}); code(err) != codes.Unauthenticated {
		t.Fatalf("no token: %v", err)
	}
	if _, err := f.c.Reclaim(tctx(t, cr.htok), &turnv1.ReclaimRequest{Room: cr.room}); code(err) != codes.Unauthenticated {
		t.Fatalf("a peer token is not a session: %v", err)
	}
	r, err := f.reclaim(cr.room, "alice")
	if err != nil || r.Host || r.Peer != cr.hid || r.HostPeer != g2 || r.Token == cr.htok {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := f.reclaim(cr.room, "alice"); code(err) != codes.PermissionDenied {
		t.Fatalf("a second reclaim: %v", err) // it is a guest now
	}
	// it is an ordinary ADMITTED guest: no knock, a join; its token is a guest's
	if err := f.decideAs("admit", cr.room, r.Token, g1); code(err) != codes.PermissionDenied {
		t.Fatalf("a returned old host decides: %v", err)
	}
	if err := f.handOver(cr.room, r.Token, g1); code(err) != codes.PermissionDenied {
		t.Fatalf("a returned old host hands over: %v", err)
	}
	if _, err := f.c.RoomCredentials(tctx(t, r.Token), &turnv1.RoomRef{Room: cr.room}); err != nil {
		t.Fatalf("an admitted guest has no credentials: %v", err)
	}
	old := f.open(cr.room, r.Token)
	var knocked, joined bool
	for _, e := range cr.gs[g2].within(150 * time.Millisecond) {
		if e.From == cr.hid && e.Kind == "sys.knock" {
			knocked = true
		}
		if e.From == cr.hid && e.Kind == "sys.join" {
			joined = true
		}
	}
	if knocked || !joined {
		t.Fatalf("knocked %v joined %v", knocked, joined)
	}
	// "host" is the same address for every sender: the old host back as a guest
	// lands on the CURRENT host; the new host addressing it is refused, and
	// reaches the old host by its real ID
	old.send(cr.hid, "host", "offer", []byte("from-old"))
	if e := cr.gs[g2].waitFor(t, "offer"); e.From != cr.hid || e.To != g2 {
		t.Fatalf("%v", e)
	}
	cr.gs[g2].send(g2, "host", "answer", []byte("self"))
	if e := cr.gs[g2].waitFor(t, "sys.error"); !strings.HasPrefix(string(e.Body), "InvalidArgument: ") {
		t.Fatalf("%v", e)
	}
	cr.gs[g2].send(g2, cr.hid, "answer", []byte("from-new"))
	if e := old.waitFor(t, "answer"); e.From != g2 || string(e.Body) != "from-new" {
		t.Fatalf("%v", e)
	}
	// a hand over leaves the others' IDs alone
	for _, g := range []string{g1, g2} {
		if f.s.rooms[cr.room].peers[g] == nil {
			t.Fatalf("%s lost its peer", g)
		}
	}
	if got := ev.all(); !strings.Contains(got, "hand_over=ok") || !strings.Contains(got, "reclaim=ok") || !strings.Contains(got, "hand_over=permission_denied") {
		t.Fatalf("events %s", got)
	}
}

func TestMessagesToTheHostInTheWindowAreCarriedToTheNewHost(t *testing.T) {
	f := newFix(t, nil)
	cr := newCrowd(t, f, 3)
	g1, g2, g3 := cr.order[0], cr.order[1], cr.order[2]
	_ = cr.host.st.CloseSend()
	f.hostLost(cr.room)
	cr.gs[g2].send(g2, "host", "update", []byte("m1"))
	cr.gs[g3].send(g3, "host", "update", []byte("m2"))
	cr.gs[g1].send(g1, "host", "update", []byte("from-the-promoted"))
	cr.gs[g3].send(g3, "host", "update", []byte("m3"))
	// the messages are in the old host's queue before the clock moves
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		f.s.mu.Lock()
		n := len(f.s.rooms[cr.room].host.queue)
		f.s.mu.Unlock()
		if n >= 4 {
			break
		}
	}
	f.advance(121)
	f.s.Sweep()
	var got []string
	for len(got) < 3 {
		e := cr.gs[g1].waitFor(t, "update")
		got = append(got, e.From+":"+string(e.Body))
	}
	// the senders' streams race each other: only each sender's own order is fixed
	set := strings.Join(got, ",")
	if !strings.Contains(set, g2+":m1") || strings.Index(set, g3+":m2") < 0 || strings.Index(set, g3+":m2") > strings.Index(set, g3+":m3") {
		t.Fatalf("carried %v", got)
	}
	// the promoted guest's own message to the host (itself, then) is not echoed
	for _, e := range cr.gs[g1].within(100 * time.Millisecond) {
		if e.Kind == "update" {
			t.Fatalf("echo %v", e)
		}
	}
}

func TestCredentialsAreChargedToThePromotedPersonWhenSignedIn(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	host := f.open(c.Room, c.Token)
	signed := f.knockAs(c.Room, "Bob", "user:bob")
	anon := f.knock(c.Room, "Anon")
	for _, g := range []*turnv1.JoinRoomResponse{signed, anon} {
		if err := f.decide("admit", c.Room, g.Peer); err != nil {
			t.Fatal(err)
		}
		f.open(c.Room, g.Token)
	}
	who := func(tok string) (string, time.Time) {
		r, err := f.c.RoomCredentials(tctx(t, tok), &turnv1.RoomRef{Room: c.Room})
		if err != nil {
			t.Fatal(err)
		}
		for _, is := range r.IceServers {
			if is.Username == "" {
				continue // the STUN entry
			}
			exp, sub, ok := creds.Parse(is.Username)
			if !ok {
				t.Fatal("bad username")
			}
			_, sub, _ = strings.Cut(sub, ".") // the keyring prefixes its key ID
			return sub, exp
		}
		t.Fatal("no TURN credentials")
		return "", time.Time{}
	}
	if sub, _ := who(anon.Token); sub != "alice" {
		t.Fatalf("before: %s", sub)
	}
	_ = host.st.CloseSend()
	f.hostLost(c.Room)
	f.advance(121)
	f.s.Sweep()
	if f.hostOf(c.Room) != signed.Peer {
		t.Fatalf("host %q", f.hostOf(c.Room))
	}
	sub, exp := who(anon.Token)
	if sub != "bob" {
		t.Fatalf("charged to %q, want the signed-in promoted person", sub)
	}
	// a handover never extends the room
	if exp.After(time.Unix(c.Expires, 0)) {
		t.Fatalf("credentials outlive the room: %v > %v", exp, time.Unix(c.Expires, 0))
	}
	// the promoted person hands on to an anonymous one: back to the original host's subject
	if err := f.handOver(c.Room, signed.Token, anon.Peer); err != nil {
		t.Fatal(err)
	}
	if sub, _ := who(anon.Token); sub != "alice" {
		t.Fatalf("an anonymous host is charged to %q, want the one who opened the room", sub)
	}
	f.s.mu.Lock()
	exp2 := f.s.rooms[c.Room].expires
	f.s.mu.Unlock()
	if exp2.Unix() != c.Expires {
		t.Fatalf("the room's TTL moved: %v -> %v", c.Expires, exp2)
	}
}

func (f *fix) knockAs(room, name, session string) *turnv1.JoinRoomResponse {
	f.t.Helper()
	j, err := f.c.JoinRoom(tctx(f.t, "", SessionMetadata, session), &turnv1.JoinRoomRequest{Room: room, Name: name})
	if err != nil {
		f.t.Fatalf("join: %v", err)
	}
	return j
}

func TestJoinWithABadSessionIsRefused(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	for _, s := range []string{"forged", "user:"} {
		if _, err := f.c.JoinRoom(tctx(t, "", SessionMetadata, s), &turnv1.JoinRoomRequest{Room: c.Room, Name: "x"}); code(err) != codes.Unauthenticated {
			t.Errorf("%q: %v", s, err)
		}
	}
	if f.s.Counts().Pending != 0 {
		t.Fatal("a refused guest is waiting")
	}
	if _, err := f.c.JoinRoom(tctx(t, "", SessionMetadata, "user:bob"), &turnv1.JoinRoomRequest{Room: c.Room, Name: "x"}); err != nil {
		t.Fatal(err) // control
	}
}

// Exactly one host at a time, whatever races: the host drops, several guests
// try to promote themselves, the host token is used again and again, and the
// janitor runs, all at once. Every peer sees the SAME single sys.host-changed.
func TestConcurrentEventsLeaveExactlyOneHost(t *testing.T) {
	for round := 0; round < 20; round++ {
		f := newFix(t, nil)
		cr := newCrowd(t, f, 4)
		_ = cr.host.st.CloseSend()
		f.hostLost(cr.room)
		f.advance(121)
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		start := make(chan struct{})
		for _, id := range cr.order {
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				if f.handOver(cr.room, cr.guest[id].Token, id) == nil { // a guest promoting itself
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
			go func() {
				defer wg.Done()
				<-start
				f.s.Sweep()
			}()
		}
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _ = f.handOver(cr.room, cr.htok, cr.order[3]) }()
		go func() { defer wg.Done(); <-start; _, _ = f.reclaim(cr.room, "alice") }()
		close(start)
		wg.Wait()
		f.s.Sweep()
		if wins != 0 {
			t.Fatalf("round %d: a guest promoted itself", round)
		}
		// whoever won, exactly one host, in the room, and every connected peer
		// saw the role move at most once, to the same peer
		f.s.mu.Lock()
		rm := f.s.rooms[cr.room]
		hosts := 0
		for _, p := range rm.peers {
			if p == rm.host {
				hosts++
			}
		}
		h := rm.host.id
		f.s.mu.Unlock()
		if hosts != 1 {
			t.Fatalf("round %d: %d hosts", round, hosts)
		}
		seen := map[string]bool{}
		for _, id := range cr.order {
			n := 0
			for _, e := range cr.gs[id].within(30 * time.Millisecond) {
				if e.Kind == "sys.host-changed" {
					n++
					_, to := hostChanged(t, e)
					seen[to] = true
				}
			}
			if n > 1 {
				t.Fatalf("round %d: %s saw %d handovers", round, id, n)
			}
		}
		if h == cr.hid {
			// the host reclaimed the role first: nobody saw a change
			if len(seen) != 0 {
				t.Fatalf("round %d: host back yet %v", round, seen)
			}
		} else if len(seen) != 1 || !seen[h] {
			t.Fatalf("round %d: host %q, peers saw %v", round, h, seen)
		}
	}
}

func TestAnExpiredRoomDoesNotPromote(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.RoomTTL = 100 * time.Second })
	cr := newCrowd(t, f, 1)
	_ = cr.host.st.CloseSend()
	f.hostLost(cr.room)
	f.advance(121) // the grace period and the room's whole life are both over
	f.s.Sweep()
	if f.s.Rooms() != 0 {
		t.Fatal("the room outlived its TTL because of a handover")
	}
	if e := cr.gs[cr.order[0]].waitFor(t, "sys.closed"); e == nil {
		t.Fatal()
	}
}

func TestGraceTimerPromotesWithoutAnySweep(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.HostGrace = 50 * time.Millisecond; c.Now = time.Now })
	cr := newCrowd(t, f, 1)
	_ = cr.host.st.CloseSend()
	e := cr.gs[cr.order[0]].waitFor(t, "sys.host-changed")
	if _, to := hostChanged(t, e); to != cr.order[0] {
		t.Fatalf("to %s", to)
	}
}

func TestSettleOnTheNextRPCWithoutTheJanitor(t *testing.T) {
	f := newFix(t, nil)
	cr := newCrowd(t, f, 2)
	_ = cr.host.st.CloseSend()
	f.hostLost(cr.room)
	f.advance(121)
	// a knock is an RPC: the room settles first, so the knock goes to the NEW host
	k := f.knock(cr.room, "late")
	if k.Host != cr.order[0] {
		t.Fatalf("knock told host %q", k.Host)
	}
	e := cr.gs[cr.order[0]].waitFor(t, "sys.knock")
	if e.From != k.Peer || e.To != cr.order[0] {
		t.Fatalf("%v", e)
	}
}

func TestObserverNeverSeesRoomState(t *testing.T) {
	ev := &events{}
	f := newFix(t, func(c *Config) { c.Observer = ev })
	cr := newCrowd(t, f, 2)
	_ = cr.host.st.CloseSend()
	f.hostLost(cr.room)
	f.advance(121)
	f.s.Sweep()
	got := ev.all()
	for _, secret := range []string{cr.room, cr.htok, "alice", "guest", cr.order[0], cr.order[1]} {
		if strings.Contains(got, secret) {
			t.Errorf("%q leaked into the events: %s", secret, got)
		}
	}
	if !strings.Contains(got, "host_lost=ok") || !strings.Contains(got, "promote=ok") {
		t.Fatalf("events %s", got)
	}
}

func TestSweepWithoutObserver(t *testing.T) {
	f := newFix(t, nil)
	f.s.Sweep()
	f.s.flushNotes(context.Background())
}
