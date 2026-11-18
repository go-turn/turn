//go:build !js

package client_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-turn/turn/rendezvous"
	"github.com/go-turn/turn/rendezvous/client"
	wstransport "github.com/grpc-transports/websocket"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const grace = 400 * time.Millisecond

func shortGrace(c *rendezvous.Config) { c.Limits.HostGrace = grace }

// lostObserver tells when the server has seen a host's stream end. A message
// sent to a host in the instant BEFORE that is written to a dead connection and
// is lost with it (nothing can tell the sender): the tests of the outage window
// start after it.
type lostObserver struct{ lost chan struct{} }

func (o lostObserver) Event(_ context.Context, action, outcome string) {
	if action == "host_lost" {
		select {
		case o.lost <- struct{}{}:
		default:
		}
	}
}

func (o lostObserver) wait(t *testing.T) {
	t.Helper()
	select {
	case <-o.lost:
	case <-time.After(5 * time.Second):
		t.Fatal("the server never saw the host's stream end")
	}
}

// until reads r's events until one is of kind.
func until(t *testing.T, r *client.Room, kind string) client.Event {
	t.Helper()
	c := ctx(t)
	for {
		e, err := r.Recv(c)
		if err != nil {
			t.Fatalf("waiting for %s: %v", kind, err)
		}
		if e.Kind == kind {
			return e
		}
	}
}

// killedHost opens a room and returns it with the means to kill its
// connection without a word, as a crashed tab does (no CloseRoom).
func killedHost(t *testing.T, base string) (*client.Room, func()) {
	t.Helper()
	cc, err := client.Dial(base, wstransport.ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	h, err := client.CreateConn(ctx(t), cc, "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	return h, func() { cc.Close() }
}

// admitted joins as name (a signed-in person when session is set) and has
// the CURRENT host admit it.
func admitted(t *testing.T, base string, host *client.Room, name string, opts ...client.JoinOption) *client.Room {
	t.Helper()
	type res struct {
		r   *client.Room
		err error
	}
	ch := make(chan res, 1)
	go func() { r, err := client.Join(ctx(t), base, host.ID, name, opts...); ch <- res{r, err} }()
	e := until(t, host, "sys.knock")
	if string(e.Body) != name {
		t.Fatalf("knock from %q, want %q", e.Body, name)
	}
	if err := host.Admit(ctx(t), e.From); err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { _ = r.r.Close(ctx(t)) })
	return r.r
}

func TestHostKilledThenPromotionThenNewcomerAndRouting(t *testing.T) {
	for _, n := range []int{2, 3} { // 3 and 4 people: the host and 2 or 3 guests
		t.Run(fmt.Sprintf("%d people", n+1), func(t *testing.T) {
			obs := lostObserver{make(chan struct{}, 1)}
			base := server(t, func(c *rendezvous.Config) { shortGrace(c); c.Observer = obs })
			host, kill := killedHost(t, base)
			var guests []*client.Room
			for i := 0; i < n; i++ {
				guests = append(guests, admitted(t, base, host, fmt.Sprintf("guest-%d", i)))
			}
			first := guests[0]
			// a message the OLD host sent to one guest only: that guest is AHEAD
			// of the one that will become the host
			if err := host.Send(ctx(t), guests[n-1].Peer, "update", []byte("only-the-last-has-me")); err != nil {
				t.Fatal(err)
			}
			if e := until(t, guests[n-1], "update"); string(e.Body) != "only-the-last-has-me" {
				t.Fatalf("%v", e)
			}
			kill()
			obs.wait(t)
			// the guests write during the outage: queued for the host, carried on
			for i, g := range guests {
				for k := 0; k < 3; k++ {
					if err := g.Send(ctx(t), "host", "update", []byte(fmt.Sprintf("%d-%d", i, k))); err != nil {
						t.Fatal(err)
					}
				}
			}
			for i, g := range guests {
				e := until(t, g, "sys.host-changed")
				from, to, ok := e.HostChange()
				if !ok || from != host.Peer || to != first.Peer {
					t.Fatalf("guest %d: %v %s %s", i, e, from, to)
				}
				if g.HostPeer() != first.Peer || g.IsHost() != (i == 0) {
					t.Fatalf("guest %d: host %s IsHost %v", i, g.HostPeer(), g.IsHost())
				}
			}
			if !first.IsHost() || first.Peer == "host" || first.Host != host.Peer {
				t.Fatalf("%+v", first)
			}
			// nothing was dropped in the window: the new host got every message
			// the guests sent while there was no host, each sender's in order,
			// except what it sent itself to itself
			got := map[string][]string{}
			want := 3 * (n - 1)
			count := 0
			for count < want {
				e := until(t, first, "update")
				if e.To != first.Peer {
					t.Fatalf("%v", e)
				}
				got[e.From] = append(got[e.From], string(e.Body))
				count++
			}
			for i := 1; i < n; i++ {
				w := fmt.Sprintf("%d-0,%d-1,%d-2", i, i, i)
				if g := strings.Join(got[guests[i].Peer], ","); g != w {
					t.Fatalf("from %s: %q, want %q", guests[i].Peer, g, w)
				}
			}
			// the guest that was ahead sends what it holds to "host": it routes to
			// the new host (the rendezvous routes, the collab layer reconciles)
			if err := guests[n-1].Send(ctx(t), "host", "update", []byte("only-the-last-has-me")); err != nil {
				t.Fatal(err)
			}
			if e := until(t, first, "update"); string(e.Body) != "only-the-last-has-me" || e.From != guests[n-1].Peer {
				t.Fatalf("%v", e)
			}
			// the new host admits a newcomer; messages route in both directions
			newcomer := admitted(t, base, first, "newcomer")
			if err := newcomer.Send(ctx(t), "host", "offer", []byte("sdp")); err != nil {
				t.Fatal(err)
			}
			if e := until(t, first, "offer"); e.From != newcomer.Peer || string(e.Body) != "sdp" {
				t.Fatalf("%v", e)
			}
			if err := first.Send(ctx(t), newcomer.Peer, "answer", []byte("sdp2")); err != nil {
				t.Fatal(err)
			}
			if e := until(t, newcomer, "answer"); e.From != first.Peer {
				t.Fatalf("%v", e)
			}
			// and it has the other powers too
			if _, err := first.Credentials(ctx(t)); err != nil {
				t.Fatal(err)
			}
			if err := first.Deny(ctx(t), newcomer.Peer); err != nil {
				t.Fatal(err)
			}
			// a guest cannot do what the host does
			if err := guests[n-1].Admit(ctx(t), newcomer.Peer); status.Code(err) == codes.OK {
				t.Fatal("a guest admitted")
			}
		})
	}
}

func TestHostBackWithinGraceIsNotReplaced(t *testing.T) {
	obs := lostObserver{make(chan struct{}, 1)}
	base := server(t, func(c *rendezvous.Config) { c.Limits.HostGrace = 5 * time.Second; c.Observer = obs })
	host, kill := killedHost(t, base)
	g := admitted(t, base, host, "bob")
	kill()
	obs.wait(t)
	if err := g.Send(ctx(t), "host", "update", []byte("while-away")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	back, err := client.Reclaim(ctx(t), base, host.ID, "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close(ctx(t))
	if !back.IsHost() || back.Peer != host.Peer || back.HostPeer() != host.Peer {
		t.Fatalf("%+v", back)
	}
	if e := until(t, back, "update"); string(e.Body) != "while-away" || e.From != g.Peer {
		t.Fatalf("%v", e)
	}
	// it hosts: it admits a newcomer, messages flow
	n := admitted(t, base, back, "carol")
	if err := n.Send(ctx(t), "host", "offer", []byte("x")); err != nil {
		t.Fatal(err)
	}
	until(t, back, "offer")
	// the guest never saw a handover, now or after the grace would have ended
	time.Sleep(grace)
	short, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	ev, err := g.Recv(short)
	if err == nil && ev.Kind == "sys.host-changed" {
		t.Fatalf("a promotion happened: %v", ev)
	}
	if g.IsHost() || g.HostPeer() != host.Peer {
		t.Fatal("the guest thinks it is the host")
	}
	// a stranger cannot reclaim
	if _, err := client.Reclaim(ctx(t), base, host.ID, "user:mallory"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("stranger: %v", err)
	}
}

func TestExplicitHandOverAndTheOldHostReturnsAsAGuest(t *testing.T) {
	base := server(t, nil)
	host := mustCreate(t, base)
	a := admitted(t, base, host, "ann", client.WithSession("user:ann"))
	b := admitted(t, base, host, "ben")
	if err := a.HandOver(ctx(t), b.Peer); err == nil {
		t.Fatal("a guest handed over")
	}
	if err := host.HandOver(ctx(t), b.Peer); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*client.Room{host, a, b} {
		if _, to, ok := until(t, r, "sys.host-changed").HostChange(); !ok || to != b.Peer {
			t.Fatalf("to %q", to)
		}
	}
	if host.IsHost() || a.IsHost() || !b.IsHost() {
		t.Fatalf("host %v ann %v ben %v", host.IsHost(), a.IsHost(), b.IsHost())
	}
	// the old host's token is dead
	if err := host.Admit(ctx(t), a.Peer); err == nil {
		t.Fatal("the old host still has its powers")
	}
	// it comes back as an ordinary peer: same peer ID, admitted, not knocking
	back, err := client.Reclaim(ctx(t), base, host.ID, "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close(ctx(t))
	if back.IsHost() || back.Peer != host.Peer || back.HostPeer() != b.Peer {
		t.Fatalf("%+v host %s", back, back.HostPeer())
	}
	// the new host is told (again) about the guests that were there, and the old
	// host's return is a join, never a knock
	for {
		e, err := b.Recv(ctx(t))
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind == "sys.knock" && e.From == host.Peer {
			t.Fatal("the old host knocked")
		}
		if e.Kind == "sys.join" && e.From == host.Peer {
			break
		}
	}
	if err := back.Send(ctx(t), "host", "update", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if e := until(t, b, "update"); e.From != host.Peer || e.To != b.Peer {
		t.Fatalf("%v", e)
	}
	// and the signed-in guest, promoted later, mints credentials as itself
	if _, err := back.Credentials(ctx(t)); err != nil {
		t.Fatal(err)
	}
}

func mustCreate(t *testing.T, base string) *client.Room {
	t.Helper()
	h, err := client.Create(ctx(t), base, "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close(ctx(t)) })
	return h
}

func TestJoinWithABadSession(t *testing.T) {
	base := server(t, nil)
	host := mustCreate(t, base)
	if _, err := client.Join(ctx(t), base, host.ID, "x", client.WithSession("forged")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("%v", err)
	}
}

func TestEventHostChange(t *testing.T) {
	for _, tc := range []struct {
		e    client.Event
		from string
		to   string
		ok   bool
	}{
		{client.Event{Kind: "sys.host-changed", Body: []byte(`{"from":"host","to":"g2"}`)}, "host", "g2", true},
		{client.Event{Kind: "sys.host-changed", Body: []byte(`{"from":"host"}`)}, "", "", false},
		{client.Event{Kind: "sys.host-changed", Body: []byte(`nope`)}, "", "", false},
		{client.Event{Kind: "sys.join", Body: []byte(`{"from":"host","to":"g2"}`)}, "", "", false},
	} {
		from, to, ok := tc.e.HostChange()
		if from != tc.from || to != tc.to || ok != tc.ok {
			t.Errorf("%v: %q %q %v", tc.e, from, to, ok)
		}
	}
}

func TestCoHostThroughTheClient(t *testing.T) {
	base := server(t, nil)
	host := mustCreate(t, base)
	a := admitted(t, base, host, "ann")
	b := admitted(t, base, host, "ben")
	if err := a.AppointCoHost(ctx(t), b.Peer); err == nil {
		t.Fatal("a guest appointed")
	}
	if err := host.AppointCoHost(ctx(t), a.Peer); err != nil {
		t.Fatal(err)
	}
	if p, added, ok := until(t, a, "sys.cohost-added").CoHost(); !ok || !added || p != a.Peer {
		t.Fatalf("%s %v %v", p, added, ok)
	}
	if !a.IsCoHost() || b.IsCoHost() || a.IsHost() {
		t.Fatalf("ann %v ben %v", a.IsCoHost(), b.IsCoHost())
	}
	// the co-host answers a knock
	c := admitted(t, base, a, "cat")
	_ = c
	if err := a.AppointCoHost(ctx(t), b.Peer); err == nil {
		t.Fatal("a co-host appointed")
	}
	if err := host.RevokeCoHost(ctx(t), a.Peer); err != nil {
		t.Fatal(err)
	}
	if _, added, ok := until(t, a, "sys.cohost-removed").CoHost(); !ok || added {
		t.Fatal("not removed")
	}
	if a.IsCoHost() {
		t.Fatal("still a co-host")
	}
	if _, _, ok := (client.Event{Kind: "sys.cohost-added", Body: []byte("x")}).CoHost(); ok {
		t.Fatal("bad body")
	}
	if _, _, ok := (client.Event{Kind: "sys.join"}).CoHost(); ok {
		t.Fatal("wrong kind")
	}
}

func TestWithMaxGuestsThroughTheClient(t *testing.T) {
	base := server(t, nil)
	if _, err := client.Create(ctx(t), base, "user:alice", client.WithMaxGuests(1000)); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("above the ceiling: %v", err)
	}
	host, err := client.Create(ctx(t), base, "user:alice", client.WithMaxGuests(1))
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(ctx(t))
	g := admitted(t, base, host, "one")
	// a second guest at once is refused: the host's Admit says why
	go func() { _, _ = client.Join(ctx(t), base, host.ID, "two") }()
	k := until(t, host, "sys.knock")
	if err := host.Admit(ctx(t), k.From); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("%v", err)
	}
	// the first leaves (Close says goodbye): its place is free at once
	if err := g.Close(ctx(t)); err != nil {
		t.Fatal(err)
	}
	until(t, host, "sys.leave")
	if err := host.Admit(ctx(t), k.From); err != nil {
		t.Fatalf("a freed place: %v", err)
	}
}
