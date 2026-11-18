package rendezvous

import (
	"strings"
	"testing"
	"time"

	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	"google.golang.org/grpc/codes"
)

func (f *fix) appoint(room, token, peer string) error {
	_, err := f.c.AppointCoHost(tctx(f.t, token), &turnv1.CoHostRequest{Room: room, Peer: peer})
	return err
}

func (f *fix) revoke(room, token, peer string) error {
	_, err := f.c.RevokeCoHost(tctx(f.t, token), &turnv1.CoHostRequest{Room: room, Peer: peer})
	return err
}

func TestCoHostAppointmentRefusals(t *testing.T) {
	ev := &events{}
	f := newFix(t, func(c *Config) { c.Observer = ev })
	cr := newCrowd(t, f, 3)
	g1, g2, g3 := cr.order[0], cr.order[1], cr.order[2]
	pend := f.knock(cr.room, "waiting")
	denied := f.knock(cr.room, "nope")
	if err := f.decide("deny", cr.room, denied.Peer); err != nil {
		t.Fatal(err)
	}
	if err := f.appoint(cr.room, cr.htok, g1); err != nil { // the control: the host can
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		revoke      bool
		token, peer string
		want        codes.Code
	}{
		"a guest appoints itself":         {false, cr.guest[g2].Token, g2, codes.PermissionDenied},
		"a guest appoints another":        {false, cr.guest[g2].Token, g3, codes.PermissionDenied},
		"a co-host appoints":              {false, cr.guest[g1].Token, g3, codes.PermissionDenied},
		"a co-host appoints itself again": {false, cr.guest[g1].Token, g1, codes.PermissionDenied},
		"a co-host revokes itself":        {true, cr.guest[g1].Token, g1, codes.PermissionDenied},
		"a guest revokes a co-host":       {true, cr.guest[g2].Token, g1, codes.PermissionDenied},
		"a pending peer is appointed":     {false, cr.htok, pend.Peer, codes.FailedPrecondition},
		"a denied peer is appointed":      {false, cr.htok, denied.Peer, codes.NotFound},
		"a stranger is appointed":         {false, cr.htok, "g99", codes.NotFound},
		"the host is appointed":           {false, cr.htok, "host", codes.InvalidArgument},
		"nobody is appointed":             {false, cr.htok, "", codes.InvalidArgument},
		"a co-host appointed twice":       {false, cr.htok, g1, codes.FailedPrecondition},
		"a guest is revoked":              {true, cr.htok, g2, codes.FailedPrecondition},
		"a pending peer is revoked":       {true, cr.htok, pend.Peer, codes.FailedPrecondition},
		"no token":                        {false, "", g2, codes.Unauthenticated},
		"a pending peer appoints":         {false, pend.Token, g2, codes.PermissionDenied},
	} {
		var err error
		if tc.revoke {
			err = f.revoke(cr.room, tc.token, tc.peer)
		} else {
			err = f.appoint(cr.room, tc.token, tc.peer)
		}
		if code(err) != tc.want {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// nothing refused changed who has powers: g2 and g3 still cannot admit
	if err := f.decideAs("admit", cr.room, cr.guest[g2].Token, pend.Peer); code(err) != codes.PermissionDenied {
		t.Fatalf("a refused appointment gave powers: %v", err)
	}
	if got := ev.all(); !strings.Contains(got, "appoint_cohost=ok") || !strings.Contains(got, "appoint_cohost=permission_denied") ||
		strings.Contains(got, g1) {
		t.Fatalf("events %s", got)
	}
}

func TestCoHostPowersAndImmediateRevocation(t *testing.T) {
	f := newFix(t, nil)
	cr := newCrowd(t, f, 3)
	g1, g2, g3 := cr.order[0], cr.order[1], cr.order[2]
	pend := f.knock(cr.room, "waiting")
	pend2 := f.knock(cr.room, "waiting too")
	ps := f.open(cr.room, pend.Token)
	_ = ps
	// control: before the appointment g1 can do none of it
	if err := f.decideAs("admit", cr.room, cr.guest[g1].Token, pend.Peer); code(err) != codes.PermissionDenied {
		t.Fatalf("%v", err)
	}
	if err := f.appoint(cr.room, cr.htok, g1); err != nil {
		t.Fatal(err)
	}
	// every peer is told, and the new co-host hears the waiting guests again
	for _, id := range cr.order {
		e := cr.gs[id].waitFor(t, "sys.cohost-added")
		if string(e.Body) != `{"peer":"`+g1+`"}` {
			t.Fatalf("%s: %s", id, e.Body)
		}
	}
	if k := cr.gs[g1].waitFor(t, "sys.knock"); k.To != g1 {
		t.Fatalf("%v", k)
	}
	if err := f.decideAs("admit", cr.room, cr.guest[g1].Token, pend.Peer); err != nil {
		t.Fatalf("a co-host cannot admit: %v", err)
	}
	// a knock now reaches the host AND the co-host
	k := f.knock(cr.room, "late")
	for {
		if e := cr.host.waitFor(t, "sys.knock"); e.From == k.Peer {
			break
		}
	}
	for {
		if e := cr.gs[g1].waitFor(t, "sys.knock"); e.From == k.Peer {
			break
		}
	}
	if err := f.decideAs("deny", cr.room, cr.guest[g1].Token, k.Peer); err != nil {
		t.Fatalf("a co-host cannot deny: %v", err)
	}
	// credentials: a co-host without a session is charged to the host's subject
	if sub := credSubject(t, f, cr.room, cr.guest[g1].Token); sub != "alice" {
		t.Fatalf("charged to %q", sub)
	}
	// a co-host cannot decide about the host or another co-host, only the host can
	if err := f.appoint(cr.room, cr.htok, g2); err != nil {
		t.Fatal(err)
	}
	if err := f.decideAs("deny", cr.room, cr.guest[g1].Token, g2); code(err) != codes.PermissionDenied {
		t.Fatalf("a co-host denied a co-host: %v", err)
	}
	if err := f.decideAs("deny", cr.room, cr.guest[g1].Token, "host"); code(err) != codes.InvalidArgument {
		t.Fatalf("a co-host denied the host: %v", err)
	}
	if err := f.handOver(cr.room, cr.guest[g1].Token, g3); code(err) != codes.PermissionDenied {
		t.Fatalf("a co-host handed over: %v", err)
	}
	// revocation is immediate: the very next call is refused
	if err := f.revoke(cr.room, cr.htok, g1); err != nil {
		t.Fatal(err)
	}
	if err := f.decideAs("admit", cr.room, cr.guest[g1].Token, pend2.Peer); code(err) != codes.PermissionDenied {
		t.Fatalf("a revoked co-host admitted: %v", err)
	}
	for _, id := range cr.order {
		e := cr.gs[id].waitFor(t, "sys.cohost-removed")
		if string(e.Body) != `{"peer":"`+g1+`"}` {
			t.Fatalf("%s: %s", id, e.Body)
		}
	}
	// the other co-host closes the room; a plain guest could not
	if _, err := f.c.CloseRoom(tctx(t, cr.guest[g3].Token), &turnv1.RoomRef{Room: cr.room}); code(err) != codes.PermissionDenied {
		t.Fatalf("a guest closed the room: %v", err)
	}
	if _, err := f.c.CloseRoom(tctx(t, cr.guest[g2].Token), &turnv1.RoomRef{Room: cr.room}); err != nil {
		t.Fatalf("a co-host cannot close: %v", err)
	}
}

func credSubject(t *testing.T, f *fix, room, tok string) string {
	t.Helper()
	r, err := f.c.RoomCredentials(tctx(t, tok), &turnv1.RoomRef{Room: room})
	if err != nil {
		t.Fatal(err)
	}
	for _, is := range r.IceServers {
		if is.Username != "" {
			_, sub, _ := strings.Cut(is.Username, ":")
			_, sub, _ = strings.Cut(sub, ".") // the keyring's key ID
			return sub
		}
	}
	t.Fatal("no TURN credentials")
	return ""
}

func TestCoHostCredentialsAreChargedToItsOwnSubject(t *testing.T) {
	f := newFix(t, nil)
	c := f.create("alice")
	signed := f.knockAs(c.Room, "Bob", "user:bob")
	anon := f.knock(c.Room, "Anon")
	f.open(c.Room, c.Token)
	for _, g := range []*turnv1.JoinRoomResponse{signed, anon} {
		if err := f.decide("admit", c.Room, g.Peer); err != nil {
			t.Fatal(err)
		}
	}
	for _, g := range []*turnv1.JoinRoomResponse{signed, anon} {
		if err := f.appoint(c.Room, c.Token, g.Peer); err != nil {
			t.Fatal(err)
		}
	}
	if sub := credSubject(t, f, c.Room, signed.Token); sub != "bob" {
		t.Fatalf("a signed-in co-host is charged to %q", sub)
	}
	if sub := credSubject(t, f, c.Room, anon.Token); sub != "alice" {
		t.Fatalf("an anonymous co-host is charged to %q", sub)
	}
	// revoked: back to the host's subject
	if err := f.revoke(c.Room, c.Token, signed.Peer); err != nil {
		t.Fatal(err)
	}
	if sub := credSubject(t, f, c.Room, signed.Token); sub != "alice" {
		t.Fatalf("a revoked co-host is charged to %q", sub)
	}
}

func TestPromotionPrefersTheEarliestAppointedCoHost(t *testing.T) {
	f := newFix(t, nil)
	cr := newCrowd(t, f, 4)
	g1, g2, g3, g4 := cr.order[0], cr.order[1], cr.order[2], cr.order[3]
	// control first: with no co-host the earliest admitted (g1) is the successor
	// (tested in TestPromotionPastGraceIsTheEarliestAdmittedGuest); now g4 is
	// appointed before g3, and g2 is a co-host that goes away
	for _, g := range []string{g4, g3, g2} {
		if err := f.appoint(cr.room, cr.htok, g); err != nil {
			t.Fatal(err)
		}
	}
	_ = cr.gs[g4].st.CloseSend() // the earliest appointed co-host is gone
	cr.host.waitFor(t, "sys.leave")
	_ = cr.host.st.CloseSend()
	f.hostLost(cr.room)
	f.advance(121)
	f.s.Sweep()
	if h := f.hostOf(cr.room); h != g3 {
		t.Fatalf("host %q, want the earliest-appointed co-host still connected (%q), not g1 (%q)", h, g3, g1)
	}
	// the promoted co-host is the host now (not also a co-host); g2 remains one
	if err := f.revoke(cr.room, cr.guest[g3].Token, g2); err != nil {
		t.Fatalf("the promoted host cannot revoke: %v", err)
	}
	// all co-hosts gone: the next loss falls back to the earliest-admitted guest
	_ = cr.gs[g3].st.CloseSend()
	f.hostLost(cr.room)
	f.advance(121)
	f.s.Sweep()
	if h := f.hostOf(cr.room); h != g1 {
		t.Fatalf("host %q, want the earliest-admitted guest %q", h, g1)
	}
}

func TestCoHostOnlyKnocksAreAnsweredAfterExpiryTooAndCoHostHearsLeaves(t *testing.T) {
	f := newFix(t, func(c *Config) { c.Limits.PendingTTL = 30 * time.Second })
	cr := newCrowd(t, f, 1)
	g1 := cr.order[0]
	if err := f.appoint(cr.room, cr.htok, g1); err != nil {
		t.Fatal(err)
	}
	k := f.knock(cr.room, "slow")
	cr.gs[g1].waitFor(t, "sys.knock")
	f.advance(31) // nobody answered: the wait expires and BOTH hear it
	f.s.Sweep()
	for name, p := range map[string]*ps{"host": cr.host, "co-host": cr.gs[g1]} {
		for {
			e := p.waitFor(t, "sys.leave")
			if e.From == k.Peer && string(e.Body) == "expired" {
				break
			}
		}
		_ = name
	}
}

// "host" is an address with ONE meaning for every sender: the current host.
func TestHostAliasLandsOnTheCurrentHostForEverySender(t *testing.T) {
	f := newFix(t, nil)
	cr := newCrowd(t, f, 3)
	g2, g3, g4 := cr.order[0], cr.order[1], cr.order[2]
	if cr.hid == "host" || g2 == "host" || g3 == "host" || g4 == "host" {
		t.Fatal("a peer is named host")
	}
	if err := f.appoint(cr.room, cr.htok, g3); err != nil {
		t.Fatal(err)
	}
	if err := f.handOver(cr.room, cr.htok, g2); err != nil { // g2 is the host now
		t.Fatal(err)
	}
	back, err := f.reclaim(cr.room, "alice") // the old host, an ordinary guest again
	if err != nil || back.Peer != cr.hid || back.Host {
		t.Fatalf("%+v %v", back, err)
	}
	old := f.open(cr.room, back.Token)
	newHost := cr.gs[g2]
	for sender, p := range map[string]*ps{cr.hid: old, g3: cr.gs[g3], g4: cr.gs[g4]} { // old host, co-host, guest
		p.send(sender, "host", "ping", []byte(sender))
		e := newHost.waitFor(t, "ping")
		if e.From != sender || e.To != g2 || string(e.Body) != sender {
			t.Errorf("to:\"host\" from %s landed as %v", sender, e)
		}
	}
	// the host addressing "host" is addressing itself: refused, said clearly
	newHost.send(g2, "host", "ping", nil)
	if e := newHost.waitFor(t, "sys.error"); !strings.HasPrefix(string(e.Body), "InvalidArgument: ") {
		t.Fatalf("%v", e)
	}
	// the real ID of the host works too, for a guest; nothing else does
	cr.gs[g4].send(g4, g2, "ping", []byte("by-id"))
	if e := newHost.waitFor(t, "ping"); string(e.Body) != "by-id" {
		t.Fatalf("%v", e)
	}
	// a v0.6 client that hard-codes "host" as the creator's ID fails clearly
	// (from is checked against the real ID the server gave), never silently
	creator := f.create("bob")
	cs := f.open(creator.Room, creator.Token)
	cs.send("host", "g99", "x", nil)
	if got := cs.ended(t); got != codes.PermissionDenied {
		t.Fatalf("a client that sends from \"host\": %v", got)
	}
}
