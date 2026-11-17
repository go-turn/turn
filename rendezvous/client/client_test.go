//go:build !js

package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-turn/turn/creds"
	"github.com/go-turn/turn/rendezvous"
	"github.com/go-turn/turn/rendezvous/client"
)

func server(t *testing.T, mod func(*rendezvous.Config)) string {
	t.Helper()
	ring, _ := creds.NewKeyring([]byte("0123456789abcdef0123"))
	cfg := rendezvous.Config{
		Auth: func(r *http.Request) (string, error) {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer user:") {
				return h[12:], nil
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
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.CloseClientConnections(); ts.Close() })
	return ts.URL
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestHandshake(t *testing.T) {
	base := server(t, nil)
	c := ctx(t)
	host, err := client.Create(c, base+"/", "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	guest, err := client.Join(c, base, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if host.Peer != "host" || guest.Host != "host" || guest.Peer == "host" || host.Expires.Before(time.Now()) {
		t.Fatalf("%+v %+v", host, guest)
	}
	if e, err := host.Recv(c); err != nil || e.Kind != "sys.join" || e.From != guest.Peer {
		t.Fatalf("%+v %v", e, err)
	}
	if err := host.Send(c, guest.Peer, "offer", "sdp-offer"); err != nil {
		t.Fatal(err)
	}
	if e, err := guest.Recv(c); err != nil || e.Kind != "offer" || e.Body != "sdp-offer" || e.From != "host" {
		t.Fatalf("%+v %v", e, err)
	}
	if err := guest.Send(c, "host", "answer", "sdp-answer"); err != nil {
		t.Fatal(err)
	}
	if e, err := host.Recv(c); err != nil || e.Kind != "answer" || e.Body != "sdp-answer" {
		t.Fatalf("%+v %v", e, err)
	}
	cr, err := guest.Credentials(c)
	if err != nil || cr.TTL <= 0 || len(cr.ICEServers) != 2 || cr.ICEServers[1].Credential == "" {
		t.Fatalf("%+v %v", cr, err)
	}
	if hc, err := client.HostCredentials(c, base, "user:alice"); err != nil || hc.TTL < 3590 || hc.TTL > 3600 {
		t.Fatalf("%+v %v", hc, err)
	}
	// the guest leaves, the host sees it, then the host closes the room.
	if err := guest.Close(c); err != nil {
		t.Fatal(err)
	}
	if e, err := host.Recv(c); err != nil || e.Kind != "sys.leave" {
		t.Fatalf("%+v %v", e, err)
	}
	if err := host.Close(c); err != nil {
		t.Fatal(err)
	}
}

func TestRecvEndsWhenRoomCloses(t *testing.T) {
	base := server(t, nil)
	c := ctx(t)
	host, _ := client.Create(c, base, "user:alice")
	guest, _ := client.Join(c, base, host.ID)
	if err := host.Close(c); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.Recv(c); !errors.Is(err, client.ErrClosed) {
		t.Fatalf("guest after the host closed: %v", err)
	}
}

func TestRecvHonoursContext(t *testing.T) {
	base := server(t, nil)
	host, _ := client.Create(ctx(t), base, "user:alice")
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := host.Recv(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

func TestRefusalsAreStatusErrors(t *testing.T) {
	base := server(t, nil)
	c := ctx(t)
	var se *client.StatusError
	if _, err := client.Create(c, base, "bad"); !errors.As(err, &se) || se.Status != 401 {
		t.Fatalf("%v", err)
	}
	if _, err := client.Join(c, base, strings.Repeat("a", 32)); !errors.As(err, &se) || se.Status != 404 || se.Message == "" {
		t.Fatalf("%v", err)
	}
	host, _ := client.Create(c, base, "user:alice")
	if err := host.Send(c, "g9", "offer", "x"); !errors.As(err, &se) || se.Status != 404 {
		t.Fatalf("%v", err)
	}
}

func TestBadInputRefusedBeforeAnyRequest(t *testing.T) {
	c := context.Background()
	for _, base := range []string{"", "ftp://x", "https://u:p@x", "https://x?q=1", "https://x#f", "//x"} {
		if _, err := client.Create(c, base, "t"); err == nil {
			t.Errorf("base %q accepted", base)
		}
	}
	if _, err := client.Join(c, "https://x", "../../etc"); err == nil {
		t.Error("room id with dots accepted")
	}
	if _, err := client.Join(c, "https://x", strings.Repeat("A", 32)); err == nil {
		t.Error("upper-case room id accepted")
	}
}

func TestParseSSE(t *testing.T) {
	in := ": hello\r\n\r\nid: 7\nevent: message\ndata: {\"a\":1}\n\n" +
		"data: line1\ndata: line2\n\n" +
		"event: closed\ndata: {}\n\n" +
		"retry: 10\nbogus: x\n\n" + // no data, no event: not dispatched
		"data: dropped, stream ends mid-event"
	var got []client.Frame
	if err := client.ParseSSE(strings.NewReader(in), func(f client.Frame) error { got = append(got, f); return nil }); err != nil {
		t.Fatal(err)
	}
	want := []client.Frame{{Event: "message", Data: `{"a":1}`, ID: "7"}, {Event: "message", Data: "line1\nline2"}, {Event: "closed", Data: "{}"}}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %+v, want %+v", i, got[i], want[i])
		}
	}
	// fn's error stops the parse
	stop := errors.New("stop")
	if err := client.ParseSSE(strings.NewReader("data: x\n\ndata: y\n\n"), func(client.Frame) error { return stop }); err != stop {
		t.Errorf("%v", err)
	}
	// a line over the bound is refused, not buffered
	if err := client.ParseSSE(strings.NewReader("data: "+strings.Repeat("a", client.MaxFrameBytes)+"\n\n"), func(client.Frame) error { return nil }); err == nil {
		t.Error("overlong line accepted")
	}
	if err := client.ParseSSE(io.MultiReader(strings.NewReader("data: x\n"), errReader{}), func(client.Frame) error { return nil }); err == nil {
		t.Error("read error swallowed")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// A stream that drops is reopened: the server kept the queue, nothing is lost.
func TestStreamReconnects(t *testing.T) {
	base := server(t, nil)
	var drops atomic.Int32
	rt := flaky{inner: client.HTTPTransport{}, drop: func() bool { return drops.Add(1) == 1 }}
	c := ctx(t)
	host, err := client.CreateWith(c, rt, base, "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	guest, _ := client.JoinWith(c, client.HTTPTransport{}, base, host.ID)
	_ = guest
	if e, err := host.Recv(c); err != nil || e.Kind != "sys.join" {
		t.Fatalf("%+v %v", e, err)
	}
	if drops.Load() < 2 {
		t.Fatalf("the stream was opened %d time(s)", drops.Load())
	}
}

type flaky struct {
	inner client.HTTPTransport
	drop  func() bool
}

func (f flaky) Do(c context.Context, m, u string, h client.Header, b []byte) (client.Response, error) {
	return f.inner.Do(c, m, u, h, b)
}

func (f flaky) Stream(c context.Context, u string, h client.Header) (io.ReadCloser, error) {
	if f.drop() {
		return nil, errors.New("network down")
	}
	return f.inner.Stream(c, u, h)
}
