//go:build js

package client

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"syscall/js"
	"testing"
	"time"
)

// These tests run under node (go_js_wasm_exec): fetch is node's, the server is
// node's http module, driven from Go callbacks.
func nodeServer(t *testing.T) string {
	t.Helper()
	http := js.Global().Call("require", "http")
	handler := js.FuncOf(func(_ js.Value, a []js.Value) any {
		req, res := a[0], a[1]
		path := req.Get("url").String()
		switch path {
		case "/echo":
			res.Call("writeHead", 201, map[string]any{"Content-Type": "application/json"})
			res.Call("end", `{"auth":"`+req.Get("headers").Get("authorization").String()+`","cookie":"`+req.Get("headers").Get("cookie").String()+`"}`)
		case "/refuse":
			res.Call("writeHead", 403, map[string]any{"Content-Type": "application/json"})
			res.Call("end", `{"error":"nope"}`)
		case "/stream":
			res.Call("writeHead", 200, map[string]any{"Content-Type": "text/event-stream"})
			res.Call("write", "event: message\ndata: {\"seq\":1,")
			js.Global().Call("setTimeout", js.FuncOf(func(js.Value, []js.Value) any {
				res.Call("write", "\"kind\":\"a\"}\n\n")
				return nil
			}), 50)
			// then stay open until the client aborts
		}
		return nil
	})
	srv := http.Call("createServer", handler)
	up := make(chan struct{})
	srv.Call("on", "listening", js.FuncOf(func(js.Value, []js.Value) any { close(up); return nil }))
	srv.Call("listen", 0, "127.0.0.1")
	<-up
	t.Cleanup(func() { srv.Call("close"); srv.Call("closeAllConnections") })
	return "http://127.0.0.1:" + strconv.Itoa(srv.Call("address").Get("port").Int())
}

func TestFetchTransport(t *testing.T) {
	base := nodeServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr := DefaultTransport()

	resp, err := tr.Do(ctx, "POST", base+"/echo", Header{"Authorization": "Bearer tok"}, []byte("{}"))
	if err != nil || resp.Status != 201 || !strings.Contains(string(resp.Body), `"auth":"Bearer tok"`) || !strings.Contains(string(resp.Body), `"cookie":"<undefined>"`) {
		t.Fatalf("%+v %v", resp, err)
	}
	if resp, err := tr.Do(ctx, "POST", base+"/refuse", nil, nil); err != nil || resp.Status != 403 {
		t.Fatalf("%+v %v", resp, err)
	}
	if _, err := tr.Do(ctx, "GET", "http://127.0.0.1:1/", nil, nil); err == nil {
		t.Fatal("connection refused not reported")
	}
	if _, err := tr.Stream(ctx, base+"/refuse", nil); err == nil {
		t.Fatal("non-200 stream accepted")
	} else {
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 403 || se.Message != "nope" {
			t.Fatalf("%v", err)
		}
	}

	// the stream arrives in two chunks and ends when the context is cancelled
	sctx, scancel := context.WithCancel(ctx)
	rc, err := tr.Stream(sctx, base+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan Frame, 1)
	end := make(chan error, 1)
	go func() { end <- ParseSSE(rc, func(f Frame) error { got <- f; return nil }) }()
	select {
	case f := <-got:
		if f.Event != "message" || f.Data != `{"seq":1,"kind":"a"}` {
			t.Fatalf("%+v", f)
		}
	case <-ctx.Done():
		t.Fatal("no frame")
	}
	scancel()
	select {
	case <-end:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end when its context was cancelled")
	}
}
