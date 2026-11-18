package rendezvous

import (
	"strings"
	"testing"
	"time"

	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	"google.golang.org/grpc/codes"
)

func TestKnockNameAndEvents(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	host := f.open(c.Room, c.Token)
	g := f.knock(c.Room, "  Bob  ")
	if e := host.next(t); e.Kind != "sys.knock" || e.From != g.Peer || string(e.Body) != "Bob" {
		t.Fatalf("%v", e)
	}
	gs := f.open(c.Room, g.Token)
	if err := f.decide("admit", c.Room, g.Peer); err != nil {
		t.Fatalf("admit %v", err)
	}
	if e := gs.next(t); e.Kind != "sys.admitted" {
		t.Fatalf("%v", e)
	}
	if e := host.next(t); e.Kind != "sys.join" || e.From != g.Peer || string(e.Body) != "Bob" {
		t.Fatalf("%v", e)
	}
	// admitted: messages and credentials now work
	gs.send(g.Peer, "host", "answer", nil)
	if e := host.next(t); e.Kind != "answer" {
		t.Fatalf("admitted guest cannot send: %v", e)
	}
	if _, err := f.c.RoomCredentials(tctx(t, g.Token), &turnv1.RoomRef{Room: c.Room}); err != nil {
		t.Fatalf("admitted guest cannot get credentials: %v", err)
	}
	// admitting twice is a failed precondition
	if err := f.decide("admit", c.Room, g.Peer); code(err) != codes.FailedPrecondition {
		t.Fatalf("second admit: %v", err)
	}
}

func TestBadNamesRefused(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	for name, n := range map[string]string{
		"newline":      "a\nb",
		"NUL":          "a\x00b",
		"escape":       "a\x1b[31mb",
		"bidi":         "a‮b",
		"line sep":     "a b",
		"too long":     strings.Repeat("a", MaxNameLen+1),
		"invalid utf8": "a\xffb", // protobuf strings must be UTF-8: refused by the codec or by us
	} {
		_, err := f.c.JoinRoom(tctx(t, ""), &turnv1.JoinRoomRequest{Room: c.Room, Name: n})
		if err == nil {
			t.Errorf("%s accepted", name)
		} else if got := code(err); got != codes.InvalidArgument && got != codes.Internal {
			t.Errorf("%s: %v", name, err)
		}
	}
	// controls: the longest name, a non-ASCII name and no name at all
	for _, n := range []string{strings.Repeat("é", MaxNameLen), "Zoë 🙂", ""} {
		f.knock(c.Room, n)
	}
}

func TestPendingGuestIsConfined(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	adm := f.join(c.Room)
	p := f.knock(c.Room, "mallory")

	// cannot send: the stream ends PERMISSION_DENIED (and the guest has left)
	ps := f.open(c.Room, p.Token)
	ps.send(p.Peer, "host", "offer", []byte("x"))
	if got := ps.ended(t); got != codes.PermissionDenied {
		t.Errorf("pending guest sent a message: %v", got)
	}
	p = f.knock(c.Room, "mallory")

	// cannot get credentials, which would spend the host's quota
	if _, err := f.c.RoomCredentials(tctx(t, p.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.PermissionDenied {
		t.Errorf("pending guest got credentials: %v", err)
	}
	// the host cannot message it either; it is told so, the stream stays open
	host := f.open(c.Room, c.Token)
	for range 5 { // knock, join, knock (the first mallory), leave, knock
		host.next(t)
	}
	host.send(c.Peer, p.Peer, "offer", nil)
	if e := host.next(t); e.Kind != "sys.error" || !strings.HasPrefix(string(e.Body), "NotFound: ") {
		t.Errorf("host message to a pending guest: %v", e)
	}
	// guests cannot decide, close, or pass messages to each other
	for _, verb := range []string{"admit", "deny"} {
		if err := f.decideAs(verb, c.Room, p.Token, p.Peer); code(err) != codes.PermissionDenied {
			t.Errorf("pending guest %ss itself: %v", verb, err)
		}
		if err := f.decideAs(verb, c.Room, adm.Token, p.Peer); code(err) != codes.PermissionDenied {
			t.Errorf("admitted guest %ss: %v", verb, err)
		}
		if err := f.decideAs(verb, c.Room, "", p.Peer); code(err) != codes.Unauthenticated {
			t.Errorf("no token %s: %v", verb, err)
		}
	}
	if _, err := f.c.CloseRoom(tctx(t, p.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.PermissionDenied {
		t.Errorf("pending guest closes the room: %v", err)
	}
	// it CAN receive events: that is how it learns the decision
	pend := f.open(c.Room, p.Token)
	if err := f.decide("admit", c.Room, p.Peer); err != nil {
		t.Fatal(err)
	}
	if e := pend.next(t); e.Kind != "sys.admitted" {
		t.Errorf("pending guest cannot receive: %v", e)
	}
	for _, who := range []string{"g99", "host", ""} {
		if err := f.decide("admit", c.Room, who); code(err) != codes.NotFound && code(err) != codes.InvalidArgument {
			t.Errorf("admit %q: %v", who, err)
		}
	}
}

func TestDenyKillsToken(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	p := f.knock(c.Room, "mallory")
	ev := f.open(c.Room, p.Token)
	if err := f.decide("deny", c.Room, p.Peer); err != nil {
		t.Fatalf("deny %v", err)
	}
	if e := ev.next(t); e.Kind != "sys.denied" {
		t.Fatalf("%v", e)
	}
	if got := ev.ended(t); got != codes.OK {
		t.Fatalf("the stream of a denied guest ends cleanly after sys.denied: %v", got)
	}
	if _, err := f.c.RoomCredentials(tctx(t, p.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.Unauthenticated {
		t.Errorf("denied token still gets credentials: %v", err)
	}
	if got := f.open(c.Room, p.Token).ended(t); got != codes.Unauthenticated {
		t.Errorf("denied token still streams: %v", got)
	}
	if err := f.decide("admit", c.Room, p.Peer); code(err) != codes.NotFound {
		t.Errorf("admitting a denied guest: %v", err)
	}
	// an admitted guest can be removed the same way
	host := f.open(c.Room, c.Token)
	a := f.join(c.Room)
	as := f.open(c.Room, a.Token)
	as.next(t)
	if err := f.decide("deny", c.Room, a.Peer); err != nil {
		t.Fatalf("remove %v", err)
	}
	if e := as.next(t); e.Kind != "sys.denied" {
		t.Fatalf("%v", e)
	}
	var left bool
	for range 8 {
		select {
		case e := <-host.ev:
			left = left || e.Kind == "sys.leave" && string(e.Body) == "removed"
		case <-time.After(300 * time.Millisecond):
		}
	}
	if !left {
		t.Error("the host is not told that an admitted guest was removed")
	}
	if _, err := f.c.RoomCredentials(tctx(t, a.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.Unauthenticated {
		t.Errorf("removed guest still has a token: %v", err)
	}
}

func TestPendingCapAndTTL(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.MaxPending = 2; c.Limits.PendingTTL = time.Minute })
	c := f.create("alice")
	a, b := f.knock(c.Room, ""), f.knock(c.Room, "")
	if _, err := f.c.JoinRoom(tctx(t, ""), &turnv1.JoinRoomRequest{Room: c.Room}); code(err) != codes.ResourceExhausted {
		t.Fatalf("third pending guest: %v", err)
	}
	// admitting one frees a pending slot (control)
	if err := f.decide("admit", c.Room, a.Peer); err != nil {
		t.Fatal(err)
	}
	f.knock(c.Room, "")
	// the pending TTL: waiting guests are dropped and told so, and the host is told
	host := f.open(c.Room, c.Token)
	bs := f.open(c.Room, b.Token)
	f.off.Store(61)
	f.s.Sweep()
	if e := bs.next(t); e.Kind != "sys.denied" || string(e.Body) != "expired" {
		t.Fatalf("%v", e)
	}
	if _, err := f.c.RoomCredentials(tctx(t, b.Token), &turnv1.RoomRef{Room: c.Room}); code(err) != codes.Unauthenticated {
		t.Errorf("expired pending token: %v", err)
	}
	leaves := 0
	for leaves < 2 {
		select {
		case e, ok := <-host.ev:
			if !ok {
				t.Fatalf("host stream ended: %v", <-host.end)
			}
			if e.Kind == "sys.leave" && string(e.Body) == "expired" {
				leaves++
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("host saw %d expired waits, want 2", leaves)
		}
	}
	// the admitted guest is untouched by the pending TTL
	if _, err := f.c.RoomCredentials(tctx(t, a.Token), &turnv1.RoomRef{Room: c.Room}); err != nil {
		t.Errorf("admitted guest dropped: %v", err)
	}
}
