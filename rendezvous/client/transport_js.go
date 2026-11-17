//go:build js

package client

import (
	"context"
	"errors"
	"io"
	"syscall/js"
)

// DefaultTransport is fetch through syscall/js.
func DefaultTransport() Transport { return FetchTransport{} }

// FetchTransport is a [Transport] over the browser's fetch. It never sends
// cookies or other ambient credentials: the Authorization header is the only one.
type FetchTransport struct{}

type result struct {
	v   js.Value
	err error
}

// await waits for a promise. The abort signal of the request makes the promise
// reject, so cancelling the context ends the wait.
func await(p js.Value) (js.Value, error) {
	ch := make(chan result, 1)
	then := js.FuncOf(func(_ js.Value, a []js.Value) any { ch <- result{v: a[0]}; return nil })
	catch := js.FuncOf(func(_ js.Value, a []js.Value) any {
		msg := "fetch failed"
		if len(a) > 0 && a[0].Type() == js.TypeObject {
			if m := a[0].Get("message"); m.Type() == js.TypeString {
				msg = m.String()
			}
		}
		ch <- result{err: errors.New("rendezvous: " + msg)}
		return nil
	})
	p.Call("then", then, catch)
	r := <-ch
	then.Release()
	catch.Release()
	return r.v, r.err
}

func request(ctx context.Context, method, url string, hd Header, body []byte) (js.Value, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(ctx)
	g := js.Global()
	opts := g.Get("Object").New()
	opts.Set("method", method)
	opts.Set("credentials", "omit")
	opts.Set("cache", "no-store")
	opts.Set("redirect", "error")
	h := g.Get("Object").New()
	for k, v := range hd {
		h.Set(k, v)
	}
	opts.Set("headers", h)
	if len(body) > 0 {
		u8 := g.Get("Uint8Array").New(len(body))
		js.CopyBytesToJS(u8, body)
		opts.Set("body", u8)
	}
	ac := g.Get("AbortController").New()
	opts.Set("signal", ac.Get("signal"))
	stop := context.AfterFunc(ctx, func() { ac.Call("abort") })
	resp, err := await(g.Call("fetch", url, opts))
	if err != nil {
		stop()
		cancel()
		return js.Value{}, nil, err
	}
	return resp, func() { stop(); ac.Call("abort"); cancel() }, nil
}

func bytesOf(buf js.Value) []byte {
	u8 := js.Global().Get("Uint8Array").New(buf)
	b := make([]byte, u8.Get("length").Int())
	js.CopyBytesToGo(b, u8)
	return b
}

// Do implements [Transport].
func (FetchTransport) Do(ctx context.Context, method, url string, hd Header, body []byte) (Response, error) {
	resp, done, err := request(ctx, method, url, hd, body)
	if err != nil {
		return Response{}, err
	}
	defer done()
	buf, err := await(resp.Call("arrayBuffer"))
	if err != nil {
		return Response{}, err
	}
	b := bytesOf(buf)
	if len(b) > maxResponse {
		return Response{}, errors.New("rendezvous: response too large")
	}
	return Response{Status: resp.Get("status").Int(), Body: b}, nil
}

const maxResponse = 1 << 20

// Stream implements [Transport]: the response body is read chunk by chunk.
func (FetchTransport) Stream(ctx context.Context, url string, hd Header) (io.ReadCloser, error) {
	hd2 := Header{"Accept": "text/event-stream"}
	for k, v := range hd {
		hd2[k] = v
	}
	resp, done, err := request(ctx, "GET", url, hd2, nil)
	if err != nil {
		return nil, err
	}
	if st := resp.Get("status").Int(); st != 200 {
		defer done()
		buf, err := await(resp.Call("arrayBuffer"))
		var b []byte
		if err == nil {
			if b = bytesOf(buf); len(b) > 4096 {
				b = b[:4096]
			}
		}
		return nil, statusErr(st, b)
	}
	reader := resp.Get("body").Call("getReader")
	pr, pw := io.Pipe()
	go func() {
		defer done()
		for {
			r, err := await(reader.Call("read"))
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			if r.Get("done").Bool() {
				pw.Close()
				return
			}
			if _, err := pw.Write(bytesOf(r.Get("value"))); err != nil {
				return // the reader closed: done() aborts the fetch
			}
		}
	}()
	return closer{pr, done}, nil
}

type closer struct {
	*io.PipeReader
	done context.CancelFunc
}

func (c closer) Close() error { c.done(); return c.PipeReader.Close() }
