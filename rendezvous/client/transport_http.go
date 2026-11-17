//go:build !js

package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"
)

// DefaultTransport is net/http, with a timeout on plain requests (streams have
// none: they end with their context).
func DefaultTransport() Transport { return HTTPTransport{} }

// HTTPTransport is a [Transport] over net/http. The zero value uses a client
// without redirects; set Client to supply TLS roots or a proxy.
type HTTPTransport struct{ Client *http.Client }

func (h HTTPTransport) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

const maxResponse = 1 << 20

// Do implements [Transport].
func (h HTTPTransport) Do(ctx context.Context, method, url string, hd Header, body []byte) (Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	for k, v := range hd {
		req.Header.Set(k, v)
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	return Response{Status: resp.StatusCode, Body: b}, err
}

// Stream implements [Transport].
func (h HTTPTransport) Stream(ctx context.Context, url string, hd Header) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	for k, v := range hd {
		req.Header.Set(k, v)
	}
	resp, err := h.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, statusErr(resp.StatusCode, b)
	}
	return resp.Body, nil
}
