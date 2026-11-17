// Package client is the rendezvous client: a real grpc-go client of
// turn.v1.Turnd, dialed over a WebSocket (github.com/grpc-transports/websocket),
// which in a browser (GOOS=js) is the browser's WebSocket through syscall/js.
//
//	room, err := client.Create(ctx, "https://turn.example.org", sessionToken)
//	// share room.ID as a link; the host's events include sys.knock:
//	ev, _ := room.Recv(ctx)           // ev.Kind == "sys.knock", ev.From the guest, ev.Body its name
//	room.Admit(ctx, ev.From)
//
//	room, err := client.Join(ctx, "https://turn.example.org", id, "Bob") // blocks until admitted
//	room.Send(ctx, "host", "answer", sdp)
//
// Join blocks until the host admits the guest: it returns [ErrDenied] if the
// host refuses it (or its wait expires) and ctx's error if ctx ends first. A
// refused message (too large, not allowed) ends the stream: Recv then returns
// the gRPC status, which status.Code reads.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/go-turn/turn/creds"
	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	wstransport "github.com/grpc-transports/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ErrClosed is returned by Recv once the room is over (expired, closed, or the
// stream ended cleanly).
var ErrClosed = errors.New("rendezvous: room closed")

// ErrDenied is returned by Join when the host refuses the guest.
var ErrDenied = errors.New("rendezvous: the host denied entry")

// Event is a message or a system event ("sys.knock", "sys.join", "sys.leave",
// "sys.admitted", "sys.denied", "sys.closed").
type Event struct {
	Seq  uint64
	From string
	To   string
	Kind string
	Body []byte
}

// WebSocketURL is the gRPC WebSocket of a turnd at base (an http(s) origin).
func WebSocketURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("rendezvous: base must be an http(s) origin without credentials, path, query or fragment")
	}
	scheme := "wss"
	if u.Scheme == "http" {
		scheme = "ws"
	}
	return scheme + "://" + u.Host + turnv1.WebSocketPath, nil
}

// Dial opens a gRPC connection to the turnd at base. Transport security is the
// WebSocket's (wss), so gRPC itself is dialed without TLS.
func Dial(base string, cfg wstransport.ClientConfig) (*grpc.ClientConn, error) {
	u, err := WebSocketURL(base)
	if err != nil {
		return nil, err
	}
	opt, err := wstransport.DialOption(u, cfg)
	if err != nil {
		return nil, err
	}
	return grpc.NewClient("passthrough:///turnd", grpc.WithTransportCredentials(insecure.NewCredentials()), opt)
}

func withToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func toCreds(r *turnv1.IceServers) creds.Response {
	out := creds.Response{TTL: int(r.GetTtl()), ICEServers: []creds.ICEServer{}}
	for _, s := range r.GetIceServers() {
		out.ICEServers = append(out.ICEServers, creds.ICEServer{URLs: s.GetUrls(), Username: s.GetUsername(), Credential: s.GetCredential()})
	}
	return out
}

// HostCredentials asks for TURN credentials for a logged-in person (a session
// token or an issuer access token).
func HostCredentials(ctx context.Context, base, token string) (creds.Response, error) {
	cc, err := Dial(base, wstransport.ClientConfig{})
	if err != nil {
		return creds.Response{}, err
	}
	defer cc.Close()
	return HostCredentialsConn(ctx, cc, token)
}

// HostCredentialsConn is [HostCredentials] over an existing connection.
func HostCredentialsConn(ctx context.Context, cc *grpc.ClientConn, token string) (creds.Response, error) {
	r, err := turnv1.NewTurndClient(cc).Credentials(withToken(ctx, token), &turnv1.CredentialsRequest{})
	if err != nil {
		return creds.Response{}, err
	}
	return toCreds(r), nil
}

// Room is a peer's membership of a room.
type Room struct {
	ID      string
	Peer    string
	Host    string // the host's peer ID, "host"
	Expires time.Time

	cc     *grpc.ClientConn
	ownsCC bool
	rpc    turnv1.TurndClient
	token  string
	stream grpc.BidiStreamingClient[turnv1.Envelope, turnv1.Envelope]
	cancel context.CancelFunc

	events chan Event
	done   chan struct{}

	sendMu sync.Mutex
	mu     sync.Mutex
	err    error
}

// Create opens a room as its host and starts receiving its events.
func Create(ctx context.Context, base, sessionToken string) (*Room, error) {
	cc, err := Dial(base, wstransport.ClientConfig{})
	if err != nil {
		return nil, err
	}
	r, err := CreateConn(ctx, cc, sessionToken)
	if err != nil {
		cc.Close()
		return nil, err
	}
	r.ownsCC = true
	return r, nil
}

// CreateConn is [Create] over an existing connection, which the caller closes.
func CreateConn(ctx context.Context, cc *grpc.ClientConn, sessionToken string) (*Room, error) {
	rpc := turnv1.NewTurndClient(cc)
	resp, err := rpc.CreateRoom(withToken(ctx, sessionToken), &turnv1.CreateRoomRequest{})
	if err != nil {
		return nil, err
	}
	return open(cc, rpc, resp.GetRoom(), resp.GetPeer(), "host", resp.GetToken(), resp.GetExpires())
}

// Join knocks at a room with its ID and a display name, and blocks until the
// host admits the guest (see the package comment).
func Join(ctx context.Context, base, roomID, name string) (*Room, error) {
	cc, err := Dial(base, wstransport.ClientConfig{})
	if err != nil {
		return nil, err
	}
	r, err := JoinConn(ctx, cc, roomID, name)
	if err != nil {
		cc.Close()
		return nil, err
	}
	r.ownsCC = true
	return r, nil
}

// JoinConn is [Join] over an existing connection, which the caller closes.
func JoinConn(ctx context.Context, cc *grpc.ClientConn, roomID, name string) (*Room, error) {
	if !validID(roomID) {
		return nil, errors.New("rendezvous: malformed room ID")
	}
	rpc := turnv1.NewTurndClient(cc)
	resp, err := rpc.JoinRoom(ctx, &turnv1.JoinRoomRequest{Room: roomID, Name: name})
	if err != nil {
		return nil, err
	}
	r, err := open(cc, rpc, resp.GetRoom(), resp.GetPeer(), resp.GetHost(), resp.GetToken(), resp.GetExpires())
	if err != nil {
		return nil, err
	}
	for { // wait for the host's decision
		e, err := r.Recv(ctx)
		if err != nil {
			r.cancel()
			switch {
			case ctx.Err() != nil:
				return nil, err
			case errors.Is(err, ErrClosed):
				return nil, ErrDenied // the stream ended without an admission
			case status.Code(err) == codes.Unauthenticated:
				// The token was good a moment ago, so the host decided before the
				// stream was open: a denial (or an expired wait) that got there first.
				return nil, ErrDenied
			case status.Code(err) == codes.NotFound:
				return nil, ErrClosed // the room ended first
			}
			return nil, err
		}
		switch e.Kind {
		case "sys.admitted":
			return r, nil
		case "sys.denied":
			r.cancel()
			return nil, ErrDenied
		case "sys.closed":
			r.cancel()
			return nil, ErrClosed
		}
	}
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

func open(cc *grpc.ClientConn, rpc turnv1.TurndClient, room, peer, host, token string, expires int64) (*Room, error) {
	sctx, cancel := context.WithCancel(context.Background())
	sctx = metadata.AppendToOutgoingContext(sctx, "authorization", "Bearer "+token, "x-turn-room", room)
	stream, err := rpc.Room(sctx)
	if err != nil {
		cancel()
		return nil, err
	}
	r := &Room{ID: room, Peer: peer, Host: host, Expires: time.Unix(expires, 0), cc: cc, rpc: rpc, token: token,
		stream: stream, cancel: cancel, events: make(chan Event, 64), done: make(chan struct{})}
	go r.pump()
	return r, nil
}

func (r *Room) pump() {
	for {
		e, err := r.stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = ErrClosed
			}
			r.finish(err)
			return
		}
		ev := Event{Seq: e.GetSeq(), From: e.GetFrom(), To: e.GetTo(), Kind: e.GetKind(), Body: e.GetBody()}
		select {
		case r.events <- ev:
		case <-r.stream.Context().Done():
			r.finish(ErrClosed)
			return
		}
		if ev.Kind == "sys.closed" {
			r.finish(ErrClosed)
			return
		}
	}
}

func (r *Room) finish(err error) {
	r.mu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.mu.Unlock()
	close(r.done)
}

func (r *Room) auth(ctx context.Context) context.Context { return withToken(ctx, r.token) }

// Send sends a message to a peer ("host" from a guest; a guest's peer ID from
// the host). A message the server refuses ends the stream: see Recv.
func (r *Room) Send(ctx context.Context, to, kind string, body []byte) error {
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	err := r.stream.Send(&turnv1.Envelope{From: r.Peer, To: to, Kind: kind, Body: body})
	if errors.Is(err, io.EOF) { // the stream has ended: the real reason is Recv's
		select {
		case <-r.done:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.err != nil {
			return r.err
		}
	}
	return err
}

// Recv returns the next event, [ErrClosed] when the room is over, the gRPC
// status that ended the stream, or ctx's error.
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

// Admit lets a knocking guest in (host only).
func (r *Room) Admit(ctx context.Context, peer string) error {
	_, err := r.rpc.Admit(r.auth(ctx), &turnv1.DecideRequest{Room: r.ID, Peer: peer})
	return err
}

// Deny refuses a knocking guest, or removes an admitted one (host only).
func (r *Room) Deny(ctx context.Context, peer string) error {
	_, err := r.rpc.Deny(r.auth(ctx), &turnv1.DecideRequest{Room: r.ID, Peer: peer})
	return err
}

// Credentials asks for TURN credentials that expire with the room (admitted
// peers only).
func (r *Room) Credentials(ctx context.Context) (creds.Response, error) {
	resp, err := r.rpc.RoomCredentials(r.auth(ctx), &turnv1.RoomRef{Room: r.ID})
	if err != nil {
		return creds.Response{}, err
	}
	return toCreds(resp), nil
}

// Close leaves the room (the host's leaving closes it) and releases the
// connection if the room dialed it.
func (r *Room) Close(ctx context.Context) error {
	var err error
	if r.Peer == "host" {
		_, err = r.rpc.CloseRoom(r.auth(ctx), &turnv1.RoomRef{Room: r.ID})
	}
	r.cancel() // ending the stream is leaving
	if r.ownsCC {
		_ = r.cc.Close()
	}
	return err
}

func (e Event) String() string {
	return fmt.Sprintf("%s %s->%s (%d bytes)", e.Kind, e.From, e.To, len(e.Body))
}
