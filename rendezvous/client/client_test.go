//go:build !js

package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-turn/turn/creds"
	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	"github.com/go-turn/turn/rendezvous"
	"github.com/go-turn/turn/rendezvous/client"
	wstransport "github.com/grpc-transports/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// server runs the real service over a real WebSocket on a real HTTP server.
func server(t *testing.T, mod func(*rendezvous.Config)) string {
	t.Helper()
	ring, _ := creds.NewKeyring([]byte("0123456789abcdef0123"))
	cfg := rendezvous.Config{
		Auth: func(_ context.Context, tok string) (string, error) {
			if s, ok := strings.CutPrefix(tok, "user:"); ok && s != "" {
				return s, nil
			}
			return "", errors.New("no")
		},
		Keyring: ring, STUN: []string{"stun:t.example:3478"}, TURN: []string{"turn:t.example:3478"},
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := rendezvous.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h, lis := wstransport.HandlerListener(wstransport.ServerConfig{Path: turnv1.WebSocketPath})
	gs := grpc.NewServer(grpc.Creds(wstransport.ServerCredentials()), grpc.MaxRecvMsgSize(s.MaxRecvMsgSize()))
	s.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	mux := http.NewServeMux()
	mux.Handle(turnv1.WebSocketPath, h)
	ts := httptest.NewServer(mux)
	t.Cleanup(func() { gs.Stop(); ts.CloseClientConnections(); ts.Close() })
	return ts.URL
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return c
}

// admitNext waits for the host's next sys.knock and admits (or denies) it.
func admitNext(t *testing.T, host *client.Room, admit bool) client.Event {
	t.Helper()
	e, err := host.Recv(ctx(t))
	if err != nil || e.Kind != "sys.knock" {
		t.Fatalf("%v %v", e, err)
	}
	if admit {
		err = host.Admit(ctx(t), e.From)
	} else {
		err = host.Deny(ctx(t), e.From)
	}
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestHandshakeWithAdmission(t *testing.T) {
	base := server(t, nil)
	c := ctx(t)
	host, err := client.Create(c, base, "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(c)

	type res struct {
		r   *client.Room
		err error
	}
	ch := make(chan res, 1)
	go func() { r, err := client.Join(c, base, host.ID, "Bob"); ch <- res{r, err} }()
	select {
	case r := <-ch:
		t.Fatalf("Join returned before the host admitted: %+v", r)
	case <-time.After(150 * time.Millisecond):
	}
	if k := admitNext(t, host, true); string(k.Body) != "Bob" {
		t.Fatalf("knock name %q", k.Body)
	}
	var guest *client.Room
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		guest = r.r
	case <-time.After(5 * time.Second):
		t.Fatal("Join did not return after the admission")
	}
	defer guest.Close(c)
	if host.Peer != "host" || guest.Host != "host" || guest.Peer == "host" || host.Expires.Before(time.Now()) {
		t.Fatalf("%+v %+v", host, guest)
	}
	if e, err := host.Recv(c); err != nil || e.Kind != "sys.join" || e.From != guest.Peer {
		t.Fatalf("%v %v", e, err)
	}
	if err := host.Send(c, guest.Peer, "offer", []byte("sdp-offer")); err != nil {
		t.Fatal(err)
	}
	if e, err := guest.Recv(c); err != nil || e.Kind != "offer" || string(e.Body) != "sdp-offer" || e.From != "host" {
		t.Fatalf("%v %v", e, err)
	}
	if err := guest.Send(c, "host", "answer", []byte("sdp-answer")); err != nil {
		t.Fatal(err)
	}
	if e, err := host.Recv(c); err != nil || e.Kind != "answer" || string(e.Body) != "sdp-answer" {
		t.Fatalf("%v %v", e, err)
	}
	cr, err := guest.Credentials(c)
	if err != nil || cr.TTL <= 0 || len(cr.ICEServers) != 2 || cr.ICEServers[1].Credential == "" {
		t.Fatalf("%+v %v", cr, err)
	}
	if hc, err := client.HostCredentials(c, base, "user:alice"); err != nil || hc.TTL < 3590 || hc.TTL > 3600 {
		t.Fatalf("%+v %v", hc, err)
	}
	// the guest leaves, the host sees it
	if err := guest.Close(c); err != nil {
		t.Fatal(err)
	}
	if e, err := host.Recv(c); err != nil || e.Kind != "sys.leave" {
		t.Fatalf("%v %v", e, err)
	}
}

func TestJoinDenied(t *testing.T) {
	base := server(t, nil)
	c := ctx(t)
	host, _ := client.Create(c, base, "user:alice")
	defer host.Close(c)
	errc := make(chan error, 1)
	go func() { _, err := client.Join(c, base, host.ID, "mallory"); errc <- err }()
	admitNext(t, host, false)
	select {
	case err := <-errc:
		if !errors.Is(err, client.ErrDenied) {
			t.Fatalf("%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Join still blocked after a denial")
	}
}

func TestJoinGivesUpWithItsContext(t *testing.T) {
	base := server(t, nil)
	host, _ := client.Create(ctx(t), base, "user:alice")
	defer host.Close(ctx(t))
	short, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := client.Join(short, base, host.ID, "x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	// leaving was part of giving up: the host is told
	e, err := host.Recv(ctx(t))
	if err != nil || e.Kind != "sys.knock" {
		t.Fatalf("%v %v", e, err)
	}
	if e, err = host.Recv(ctx(t)); err != nil || e.Kind != "sys.leave" {
		t.Fatalf("a guest that gave up did not leave: %v %v", e, err)
	}
}

func TestRecvEndsWhenRoomCloses(t *testing.T) {
	base := server(t, nil)
	c := ctx(t)
	host, _ := client.Create(c, base, "user:alice")
	gch := make(chan *client.Room, 1)
	go func() { g, _ := client.Join(c, base, host.ID, "g"); gch <- g }()
	admitNext(t, host, true)
	guest := <-gch
	if err := host.Close(c); err != nil {
		t.Fatal(err)
	}
	for {
		e, err := guest.Recv(c)
		if err != nil {
			if !errors.Is(err, client.ErrClosed) {
				t.Fatalf("guest after the host closed: %v", err)
			}
			break
		}
		if e.Kind != "sys.closed" && e.Kind != "sys.join" {
			t.Fatalf("%v", e)
		}
	}
}

func TestRecvHonoursContext(t *testing.T) {
	base := server(t, nil)
	host, _ := client.Create(ctx(t), base, "user:alice")
	defer host.Close(ctx(t))
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := host.Recv(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

func TestRefusalsAreStatuses(t *testing.T) {
	base := server(t, func(c *rendezvous.Config) { c.Limits.MaxMessageBytes = 100 })
	c := ctx(t)
	if _, err := client.Create(c, base, "bad"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("%v", err)
	}
	if _, err := client.Join(c, base, strings.Repeat("a", 32), "x"); status.Code(err) != codes.NotFound {
		t.Fatalf("%v", err)
	}
	host, _ := client.Create(c, base, "user:alice")
	defer host.Close(c)
	gch := make(chan *client.Room, 1)
	go func() { g, _ := client.Join(c, base, host.ID, "g"); gch <- g }()
	admitNext(t, host, true)
	guest := <-gch
	// a pending-or-not guest cannot become host
	if err := guest.Admit(c, guest.Peer); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("guest admitting: %v", err)
	}
	// an oversized message ends the stream with RESOURCE_EXHAUSTED, which Recv reports
	_ = guest.Send(c, "host", "answer", []byte(strings.Repeat("a", 101)))
	for {
		_, err := guest.Recv(c)
		if err == nil {
			continue
		}
		if status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("%v", err)
		}
		break
	}
	// and Send then reports the same status, not a bare EOF
	if err := guest.Send(c, "host", "x", nil); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("send after the stream ended: %v", err)
	}
}

func TestBadInputRefusedBeforeAnyRequest(t *testing.T) {
	c := context.Background()
	for _, base := range []string{"", "ftp://x", "https://u:p@x", "https://x?q=1", "https://x#f", "//x", "https://x/path"} {
		if _, err := client.Create(c, base, "t"); err == nil {
			t.Errorf("base %q accepted", base)
		}
	}
	if _, err := client.Join(c, "https://x", "../../etc", "n"); err == nil {
		t.Error("room id with dots accepted")
	}
	if _, err := client.Join(c, "https://x", strings.Repeat("A", 32), "n"); err == nil {
		t.Error("upper-case room id accepted")
	}
	for in, want := range map[string]string{"https://t.example": "wss://t.example/grpc", "http://127.0.0.1:8080/": "ws://127.0.0.1:8080/grpc"} {
		if got, err := client.WebSocketURL(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v", in, got, err)
		}
	}
}
