package rendezvous

import (
	"context"
	"strings"
	"testing"
	"time"

	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	"google.golang.org/grpc/codes"
)

// openCancelable opens a Room stream that the test can cut like a broken
// connection (a cancel, not a half-close).
func (f *fix) openCancelable(room, token string) (*ps, context.CancelFunc) {
	f.t.Helper()
	ctx, cancel := context.WithCancel(tctx(f.t, token, RoomMetadata, room))
	st, err := f.c.Room(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	p := &ps{st: st, ev: make(chan *turnv1.Envelope, 256), end: make(chan error, 1)}
	go func() {
		for {
			e, err := st.Recv()
			if err != nil {
				close(p.ev)
				p.end <- err
				return
			}
			p.ev <- e
		}
	}()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline) && !f.streaming(room, token); time.Sleep(time.Millisecond) {
	}
	return p, cancel
}

func (f *fix) notStreaming(room, token string) {
	f.t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if !f.streaming(room, token) {
			return
		}
	}
	f.t.Fatal("the server still sees the stream")
}

func (f *fix) admit(room, htok, peer string) error { return f.decideAs("admit", room, htok, peer) }

func TestMaxGuestsIsConcurrentNotLifetime(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxGuests = 2; c.Limits.MaxAdmissions = 100 })
	c := f.create("alice")
	a, b := f.knock(c.Room, "a"), f.knock(c.Room, "b")
	third := f.knock(c.Room, "c")
	for _, g := range []*turnv1.JoinRoomResponse{a, b} {
		if err := f.admit(c.Room, c.Token, g.Peer); err != nil {
			t.Fatal(err)
		}
	}
	// control: the cap is real
	err := f.admit(c.Room, c.Token, third.Peer)
	if code(err) != codes.ResourceExhausted || !strings.Contains(err.Error(), "2 guests at once") {
		t.Fatalf("a third guest at once: %v", err)
	}
	// a guest leaves (half-close): its place is free
	as := f.open(c.Room, a.Token)
	as.next(t)
	_ = as.st.CloseSend()
	f.notStreaming(c.Room, a.Token)
	if err := f.admit(c.Room, c.Token, third.Peer); err != nil {
		t.Fatalf("a place freed by a departure is not reusable: %v", err)
	}
	// a denial frees one too
	fourth := f.knock(c.Room, "d")
	if code(f.admit(c.Room, c.Token, fourth.Peer)) != codes.ResourceExhausted {
		t.Fatal("full again")
	}
	if err := f.decide("deny", c.Room, b.Peer); err != nil {
		t.Fatal(err)
	}
	if err := f.admit(c.Room, c.Token, fourth.Peer); err != nil {
		t.Fatalf("a place freed by a denial: %v", err)
	}
	// an absence that expired frees one: five Wi-Fi drops never fill the room
	f.s.mu.Lock()
	n := len(f.s.rooms[c.Room].peers)
	f.s.mu.Unlock()
	ts, cancel := f.openCancelable(c.Room, third.Token)
	ts.next(t)
	cancel()
	f.notStreaming(c.Room, third.Token)
	fifth := f.knock(c.Room, "e")
	if code(f.admit(c.Room, c.Token, fifth.Peer)) != codes.ResourceExhausted {
		t.Fatal("a guest that may resume still holds its place")
	}
	f.advance(31)
	f.s.Sweep()
	if err := f.admit(c.Room, c.Token, fifth.Peer); err != nil {
		t.Fatalf("an expired absence did not free its place: %v", err)
	}
	_ = n
}

func TestMaxAdmissionsBoundsTheChurn(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxGuests = 2; c.Limits.MaxAdmissions = 3 })
	c := f.create("alice")
	for i := 0; i < 3; i++ { // three admissions, each guest leaving: never more than 1 at once
		g := f.knock(c.Room, "g")
		if err := f.admit(c.Room, c.Token, g.Peer); err != nil {
			t.Fatalf("admission %d: %v", i, err)
		}
		if err := f.decide("deny", c.Room, g.Peer); err != nil {
			t.Fatal(err)
		}
	}
	g := f.knock(c.Room, "one too many")
	err := f.admit(c.Room, c.Token, g.Peer)
	if code(err) != codes.ResourceExhausted || !strings.Contains(err.Error(), "in its life") || strings.Contains(err.Error(), "at once") {
		t.Fatalf("the cumulative cap says what it is: %v", err)
	}
}

func TestADroppedGuestResumesWithItsTokenAndConsumesNothing(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxGuests = 3; c.Limits.MaxAdmissions = 3 })
	c := f.create("alice")
	host := f.open(c.Room, c.Token)
	g := f.join(c.Room)
	gs, cancel := f.openCancelable(c.Room, g.Token)
	gs.waitFor(t, "sys.admitted")
	admissions := func() (int, int) {
		f.s.mu.Lock()
		defer f.s.mu.Unlock()
		rm := f.s.rooms[c.Room]
		return rm.admissions, rm.guestsLocked()
	}
	adm0, guests0 := admissions()
	if adm0 != 1 || guests0 != 1 {
		t.Fatalf("%d %d", adm0, guests0)
	}
	cancel() // the Wi-Fi drops: not a goodbye
	f.notStreaming(c.Room, g.Token)
	f.advance(10) // within the grace
	f.s.Sweep()
	// the host was NOT told the guest left, the token is alive
	for _, e := range host.within(80 * time.Millisecond) {
		if e.Kind == "sys.leave" {
			t.Fatalf("a dropped guest is said to have left: %v", e)
		}
	}
	if _, err := f.c.RoomCredentials(tctx(t, g.Token), &turnv1.RoomRef{Room: c.Room}); err != nil {
		t.Fatalf("a dropped guest lost its token: %v", err)
	}
	// it resumes: same peer, no knock, nothing consumed, and it is routable again
	back, cancelBack := f.openCancelable(c.Room, g.Token)
	back.send(g.Peer, "host", "hello", []byte("again"))
	if e := host.waitFor(t, "hello"); e.From != g.Peer {
		t.Fatalf("%v", e)
	}
	for i := 0; i < 5; i++ { // five more drops and resumptions fill nothing
		cancelBack()
		f.notStreaming(c.Room, g.Token)
		_, cancelBack = f.openCancelable(c.Room, g.Token)
	}
	cancelBack()
	if adm, guests := admissions(); adm != adm0 || guests != guests0 {
		t.Fatalf("a resumption consumed something: admissions %d, guests %d", adm, guests)
	}
	// control: a goodbye (half-close) is a departure at once: the token is dead
	g2 := f.join(c.Room)
	g2s := f.open(c.Room, g2.Token)
	g2s.waitFor(t, "sys.admitted")
	_ = g2s.st.CloseSend()
	if e := host.waitFor(t, "sys.leave"); e.From != g2.Peer {
		t.Fatalf("%v", e)
	}
	if _, err := f.c.RoomCredentials(tctx(t, g2.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.Unauthenticated {
		t.Fatalf("a guest that said goodbye kept its token: %v", err)
	}
}

func TestAnAbsenceThatLastsEndsWithALeave(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	host := f.open(c.Room, c.Token)
	g := f.join(c.Room)
	gs, cancel := f.openCancelable(c.Room, g.Token)
	gs.waitFor(t, "sys.admitted")
	cancel()
	f.notStreaming(c.Room, g.Token)
	f.advance(31)
	f.s.Sweep()
	if e := host.waitFor(t, "sys.leave"); e.From != g.Peer {
		t.Fatalf("%v", e)
	}
	if _, err := f.c.RoomCredentials(tctx(t, g.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.Unauthenticated {
		t.Fatalf("an expired absence kept its token: %v", err)
	}
	// and with the grace off a drop is a departure at once
	f2 := newFix(t, func(c *Config) { c.Limits.GuestGrace = -1 })
	c2 := f2.create("alice")
	g2 := f2.join(c2.Room)
	s2, cancel2 := f2.openCancelable(c2.Room, g2.Token)
	s2.waitFor(t, "sys.admitted")
	cancel2()
	f2.notStreaming(c2.Room, g2.Token)
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if f2.s.Counts().Guests == 0 {
			return
		}
	}
	t.Fatal("GuestGrace < 0 kept a dropped guest")
}

func TestAHandoverConsumesNoAdmission(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxGuests = 8; c.Limits.MaxAdmissions = 5 })
	cr := newCrowd(t, f, 5)
	count := func() (int, int) {
		f.s.mu.Lock()
		defer f.s.mu.Unlock()
		rm := f.s.rooms[cr.room]
		return rm.admissions, rm.guestsLocked()
	}
	adm0, g0 := count()
	if adm0 != 5 || g0 != 5 {
		t.Fatalf("%d %d", adm0, g0)
	}
	if err := f.handOver(cr.room, cr.htok, cr.order[2]); err != nil {
		t.Fatal(err)
	}
	if adm, _ := count(); adm != adm0 {
		t.Fatalf("a handover consumed %d admission(s)", adm-adm0)
	}
	back, err := f.reclaim(cr.room, "alice") // the old host returns as a guest
	if err != nil || back.Host {
		t.Fatalf("%+v %v", back, err)
	}
	if adm, g := count(); adm != adm0 || g != g0 { // the promoted guest left the guests, the old host joined them
		t.Fatalf("after the return: admissions %d, guests %d", adm, g)
	}
	// control: the admission budget is spent (5 of 5): a newcomer is refused
	late := f.knock(cr.room, "late")
	if err := f.admit(cr.room, cr.guest[cr.order[2]].Token, late.Peer); code(err) != codes.ResourceExhausted {
		t.Fatalf("%v", err)
	}
}

func TestMaxGuestsPerRoomUnderTheServersCeiling(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxGuests = 12 })
	mk := func(n int32) (*turnv1.CreateRoomResponse, error) {
		return f.c.CreateRoom(tctx(t, "user:alice"), &turnv1.CreateRoomRequest{MaxGuests: n})
	}
	// default 8 although the ceiling is 12
	d, err := mk(0)
	if err != nil || d.MaxGuests != 8 {
		t.Fatalf("%+v %v", d, err)
	}
	// a room asks for less, or for more up to the ceiling
	for _, n := range []int32{1, 3, 12} {
		r, err := mk(n)
		if err != nil || r.MaxGuests != n {
			t.Fatalf("%d: %+v %v", n, r, err)
		}
	}
	for _, n := range []int32{13, 1000, -1} {
		if _, err := mk(n); code(err) != codes.InvalidArgument {
			t.Errorf("%d: %v", n, err)
		}
	}
	// the cap of the room is the one enforced
	r, err := f.c.CreateRoom(tctx(t, "user:bob"), &turnv1.CreateRoomRequest{MaxGuests: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		g := f.knock(r.Room, "g")
		if err := f.admit(r.Room, r.Token, g.Peer); err != nil {
			t.Fatal(err)
		}
	}
	g := f.knock(r.Room, "g")
	if err := f.admit(r.Room, r.Token, g.Peer); code(err) != codes.ResourceExhausted {
		t.Fatalf("%v", err)
	}
	// and a ceiling under 8 lowers the default
	f2 := newFix(t, func(c *Config) { c.Limits.MaxGuests = 3 })
	d2, err := f2.c.CreateRoom(tctx(t, "user:alice"), &turnv1.CreateRoomRequest{})
	if err != nil || d2.MaxGuests != 3 {
		t.Fatalf("%+v %v", d2, err)
	}
}
