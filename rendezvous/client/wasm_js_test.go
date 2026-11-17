//go:build js

package client

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestWasmRoundTrip runs the whole client in wasm (under node, with its
// WebSocket). It needs a server: TestWasmEndToEnd (native) starts one and
// passes its URL.
func TestWasmRoundTrip(t *testing.T) {
	base := os.Getenv("TURND_URL")
	if base == "" {
		t.Skip("TURND_URL is set by the native TestWasmEndToEnd")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	host, err := Create(ctx, base, "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	type res struct {
		r   *Room
		err error
	}
	ch := make(chan res, 1)
	go func() { r, err := Join(ctx, base, host.ID, "Wasm Guest"); ch <- res{r, err} }()
	e, err := host.Recv(ctx)
	if err != nil || e.Kind != "sys.knock" || string(e.Body) != "Wasm Guest" {
		t.Fatalf("%v %v", e, err)
	}
	if err := host.Admit(ctx, e.From); err != nil {
		t.Fatal(err)
	}
	g := <-ch
	if g.err != nil {
		t.Fatal(g.err)
	}
	if e, err = host.Recv(ctx); err != nil || e.Kind != "sys.join" {
		t.Fatalf("%v %v", e, err)
	}
	if err := g.r.Send(ctx, "host", "answer", []byte("sdp")); err != nil {
		t.Fatal(err)
	}
	if e, err = host.Recv(ctx); err != nil || e.Kind != "answer" || string(e.Body) != "sdp" {
		t.Fatalf("%v %v", e, err)
	}
	if cr, err := g.r.Credentials(ctx); err != nil || len(cr.ICEServers) == 0 {
		t.Fatalf("%+v %v", cr, err)
	}
	if err := g.r.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := host.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
