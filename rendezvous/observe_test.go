package rendezvous

import (
	"context"
	"strings"
	"sync"
	"testing"

	turnv1 "github.com/go-turn/turn/proto/turn/v1"
)

type events struct {
	mu  sync.Mutex
	got []string
}

func (e *events) Event(_ context.Context, action, outcome string) {
	e.mu.Lock()
	e.got = append(e.got, action+"="+outcome)
	e.mu.Unlock()
}

func (e *events) all() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return strings.Join(e.got, " ")
}

func TestObserverSeesEveryRPCOutcome(t *testing.T) {
	ev := &events{}
	f := newFix(t, func(c *Config) { c.Observer = ev; c.Limits.MaxRoomsPerSubject = 1 })
	room := f.create("alice")
	// a second room is refused: ResourceExhausted, in snake case
	if _, err := f.c.CreateRoom(tctx(t, "user:alice"), &turnv1.CreateRoomRequest{}); err == nil {
		t.Fatal("want refusal")
	}
	if _, err := f.c.CreateRoom(tctx(t, "forged"), &turnv1.CreateRoomRequest{}); err == nil {
		t.Fatal("want refusal")
	}
	if _, err := f.c.Credentials(tctx(t, "user:alice"), &turnv1.CredentialsRequest{}); err != nil {
		t.Fatal(err)
	}
	g := f.knock(room.Room, "Bob")
	if _, err := f.c.RoomCredentials(tctx(t, g.Token), &turnv1.RoomRef{Room: room.Room}); err == nil {
		t.Fatal("a pending guest must be refused")
	}
	if _, err := f.c.Admit(tctx(t, room.Token), &turnv1.DecideRequest{Room: room.Room, Peer: g.Peer}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.RoomCredentials(tctx(t, g.Token), &turnv1.RoomRef{Room: room.Room}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.Deny(tctx(t, room.Token), &turnv1.DecideRequest{Room: room.Room, Peer: g.Peer}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.CloseRoom(tctx(t, room.Token), &turnv1.RoomRef{Room: room.Room}); err != nil {
		t.Fatal(err)
	}
	got := ev.all()
	for _, want := range []string{"create_room=ok", "create_room=resource_exhausted", "create_room=unauthenticated", "credentials_host=ok",
		"knock=ok", "credentials_room=permission_denied", "admit=ok", "credentials_room=ok", "deny=ok", "close_room=ok"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	// an event is only an action and an outcome: no token, room or peer ID
	for _, secret := range []string{room.Room, room.Token, g.Token, "alice", "Bob", "forged"} {
		if strings.Contains(got, secret) {
			t.Errorf("%q leaked into the events: %s", secret, got)
		}
	}
}

func TestCountsRoomsPendingAndAdmitted(t *testing.T) {
	f := newFix(t, nil)
	if c := f.s.Counts(); c != (Counts{}) {
		t.Fatalf("empty: %+v", c)
	}
	a := f.create("alice")
	f.create("carol")
	f.knock(a.Room, "Bob")
	f.join(a.Room)
	if c := f.s.Counts(); c != (Counts{Rooms: 2, Pending: 1, Guests: 1}) {
		t.Fatalf("counts %+v", c)
	}
}

func TestSnake(t *testing.T) {
	for in, want := range map[string]string{"Unauthenticated": "unauthenticated", "ResourceExhausted": "resource_exhausted",
		"FailedPrecondition": "failed_precondition", "NotFound": "not_found"} {
		if got := snake(in); got != want {
			t.Errorf("snake(%q) = %q, want %q", in, got, want)
		}
	}
}
