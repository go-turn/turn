// Package client is the rendezvous client. Its logic is plain Go over a small
// [Transport]; in a browser (GOOS=js) the transport is fetch through syscall/js,
// natively it is net/http, so the logic is covered by ordinary tests.
//
// The event stream is a fetch whose body is read incrementally, not an
// EventSource: EventSource cannot send an Authorization header, and a peer
// token in a URL would end up in logs and history.
//
//	room, err := client.Create(ctx, "https://turn.example.org", sessionToken)
//	// share room.ID as a link; the guest does:
//	room, err := client.Join(ctx, "https://turn.example.org", id)
//	room.Send(ctx, "host", "answer", sdp)
//	ev, err := room.Recv(ctx)
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-turn/turn/creds"
)

// Header is a request's headers.
type Header map[string]string

// Response is a completed request.
type Response struct {
	Status int
	Body   []byte
}

// Transport carries the HTTP. Stream opens a GET whose body is read
// incrementally; a non-200 status is a *[StatusError].
type Transport interface {
	Do(ctx context.Context, method, url string, h Header, body []byte) (Response, error)
	Stream(ctx context.Context, url string, h Header) (io.ReadCloser, error)
}

// StatusError is a refusal by the server.
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("rendezvous: %d %s", e.Status, e.Message) }

// ErrClosed is returned by Recv once the room is over (expired or closed).
var ErrClosed = errors.New("rendezvous: room closed")

// Event is a message or a system event ("sys.join", "sys.leave").
type Event struct {
	Seq  uint64 `json:"seq"`
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
	Body string `json:"body"`
}

type message struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
	Body string `json:"body"`
}

type roomJSON struct {
	Room    string `json:"room"`
	Peer    string `json:"peer"`
	Host    string `json:"host"`
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
}

// Room is a peer's membership of a room.
type Room struct {
	ID      string
	Peer    string
	Host    string // "host", the host's peer ID
	Expires time.Time

	t      Transport
	base   string
	token  string
	events chan Event
	cancel context.CancelFunc
	done   chan struct{}

	mu  sync.Mutex
	err error
}

func normBase(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("rendezvous: base must be an http(s) URL without credentials, query or fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func bearer(tok string) Header { return Header{"Authorization": "Bearer " + tok} }

func call(ctx context.Context, t Transport, method, u string, h Header, body any, out any) error {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return err
		}
		if h == nil {
			h = Header{}
		}
		h["Content-Type"] = "application/json"
	}
	resp, err := t.Do(ctx, method, u, h, b)
	if err != nil {
		return err
	}
	if resp.Status/100 != 2 {
		return statusErr(resp.Status, resp.Body)
	}
	if out != nil {
		return json.Unmarshal(resp.Body, out)
	}
	return nil
}

func statusErr(status int, body []byte) *StatusError {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(bytes.TrimSpace(body), &e)
	return &StatusError{Status: status, Message: e.Error}
}

// HostCredentials asks for TURN credentials for a logged-in person.
func HostCredentials(ctx context.Context, base, sessionToken string) (creds.Response, error) {
	return HostCredentialsWith(ctx, DefaultTransport(), base, sessionToken)
}

// HostCredentialsWith is [HostCredentials] over t.
func HostCredentialsWith(ctx context.Context, t Transport, base, sessionToken string) (creds.Response, error) {
	var r creds.Response
	b, err := normBase(base)
	if err != nil {
		return r, err
	}
	return r, call(ctx, t, "POST", b+"/credentials", bearer(sessionToken), nil, &r)
}

// Create opens a room as its host, with a turnd session token, and starts
// receiving its events.
func Create(ctx context.Context, base, sessionToken string) (*Room, error) {
	return CreateWith(ctx, DefaultTransport(), base, sessionToken)
}

// CreateWith is [Create] over t.
func CreateWith(ctx context.Context, t Transport, base, sessionToken string) (*Room, error) {
	b, err := normBase(base)
	if err != nil {
		return nil, err
	}
	var rj roomJSON
	if err := call(ctx, t, "POST", b+"/rooms", bearer(sessionToken), nil, &rj); err != nil {
		return nil, err
	}
	rj.Host = "host"
	return start(t, b, rj), nil
}

// Join enters a room as a guest, with the room ID as the only credential.
func Join(ctx context.Context, base, roomID string) (*Room, error) {
	return JoinWith(ctx, DefaultTransport(), base, roomID)
}

// JoinWith is [Join] over t.
func JoinWith(ctx context.Context, t Transport, base, roomID string) (*Room, error) {
	b, err := normBase(base)
	if err != nil {
		return nil, err
	}
	if !validID(roomID) {
		return nil, errors.New("rendezvous: malformed room ID")
	}
	var rj roomJSON
	if err := call(ctx, t, "POST", b+"/rooms/"+roomID+"/join", nil, nil, &rj); err != nil {
		return nil, err
	}
	return start(t, b, rj), nil
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func start(t Transport, base string, rj roomJSON) *Room {
	ctx, cancel := context.WithCancel(context.Background())
	r := &Room{ID: rj.Room, Peer: rj.Peer, Host: rj.Host, Expires: time.Unix(rj.Expires, 0),
		t: t, base: base, token: rj.Token, events: make(chan Event, 64), cancel: cancel, done: make(chan struct{})}
	go r.pump(ctx)
	return r
}

func (r *Room) url(suffix string) string { return r.base + "/rooms/" + r.ID + suffix }

// Send sends a message to a peer ("host" from a guest; a guest's peer ID from
// the host).
func (r *Room) Send(ctx context.Context, to, kind, body string) error {
	return call(ctx, r.t, "POST", r.url("/messages"), bearer(r.token), message{From: r.Peer, To: to, Kind: kind, Body: body}, nil)
}

// Credentials asks for TURN credentials that expire with the room.
func (r *Room) Credentials(ctx context.Context) (creds.Response, error) {
	var c creds.Response
	return c, call(ctx, r.t, "POST", r.url("/credentials"), bearer(r.token), nil, &c)
}

// Recv returns the next event, or [ErrClosed] when the room is over, or the
// error that ended the stream, or ctx's error.
func (r *Room) Recv(ctx context.Context) (Event, error) {
	select {
	case e := <-r.events:
		return e, nil
	default:
	}
	select {
	case e := <-r.events:
		return e, nil
	case <-r.done:
		select { // events delivered before the end are still owed
		case e := <-r.events:
			return e, nil
		default:
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		return Event{}, r.err
	case <-ctx.Done():
		return Event{}, ctx.Err()
	}
}

// Close leaves the room (the host's leaving closes it) and stops the stream.
func (r *Room) Close(ctx context.Context) error {
	var err error
	if r.Peer == r.Host {
		err = call(ctx, r.t, "DELETE", r.url(""), bearer(r.token), nil, nil)
	} else {
		err = call(ctx, r.t, "POST", r.url("/leave"), bearer(r.token), nil, nil)
	}
	r.cancel()
	return err
}

func (r *Room) finish(err error) {
	r.mu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.mu.Unlock()
	close(r.done)
}

// reconnect schedule: the server keeps a peer's queue, so a dropped stream
// loses nothing; give up after a few consecutive failures.
var backoff = []time.Duration{200 * time.Millisecond, time.Second, 3 * time.Second, 10 * time.Second}

func (r *Room) pump(ctx context.Context) {
	failures := 0
	for {
		rc, err := r.t.Stream(ctx, r.url("/events"), bearer(r.token))
		if err == nil {
			got := false
			err = ParseSSE(rc, func(f Frame) error {
				got = true
				switch f.Event {
				case "closed":
					return ErrClosed
				case "message":
					var e Event
					if json.Unmarshal([]byte(f.Data), &e) != nil {
						return errors.New("rendezvous: bad event from the server")
					}
					select {
					case r.events <- e:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return nil
			})
			_ = rc.Close()
			if got {
				failures = 0
			}
			if errors.Is(err, ErrClosed) {
				r.finish(ErrClosed)
				return
			}
		}
		var se *StatusError
		switch {
		case ctx.Err() != nil:
			r.finish(ErrClosed)
			return
		case errors.As(err, &se) && se.Status == 404:
			r.finish(ErrClosed) // the room is gone (closed or expired)
			return
		case errors.As(err, &se) && se.Status != 409 && se.Status < 500:
			r.finish(err) // 401: our token is no longer good
			return
		case failures >= len(backoff):
			r.finish(fmt.Errorf("rendezvous: event stream lost: %w", err))
			return
		}
		select {
		case <-time.After(backoff[failures]):
		case <-ctx.Done():
			r.finish(ErrClosed)
			return
		}
		failures++
	}
}
