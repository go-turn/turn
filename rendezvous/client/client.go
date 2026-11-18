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
	"encoding/json"
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
// "sys.admitted", "sys.denied", "sys.closed", "sys.host-changed").
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

// Session is a session token and when it expires.
type Session struct {
	Token   string
	Expires time.Time
}

// RenewSession trades a session token, valid or just expired (turnd's grace is
// 5 minutes), for a new one, without another login. A gRPC status of
// Unauthenticated means it cannot be renewed (it predates renewal, turnd
// restarted, the identity provider revoked the session or its renewal lifetime
// is over): sign in again. Unavailable means turnd could not reach the provider
// and the session is intact: retry.
func RenewSession(ctx context.Context, base, token string) (Session, error) {
	cc, err := Dial(base, wstransport.ClientConfig{})
	if err != nil {
		return Session{}, err
	}
	defer cc.Close()
	return RenewSessionConn(ctx, cc, token)
}

// RenewSessionConn is [RenewSession] over an existing connection.
func RenewSessionConn(ctx context.Context, cc *grpc.ClientConn, token string) (Session, error) {
	r, err := turnv1.NewTurndClient(cc).RenewSession(withToken(ctx, token), &turnv1.RenewSessionRequest{})
	if err != nil {
		return Session{}, err
	}
	return Session{Token: r.GetToken(), Expires: time.Unix(r.GetExpires(), 0)}, nil
}

// retryUnavailable is the wait before KeepRenewed retries an Unavailable answer
// (a variable for tests).
var retryUnavailable = 30 * time.Second

// KeepRenewed renews cur ahead of its expiry until ctx ends, and calls update
// with every new session (store the token, use it for the next call). It
// renews when `lead` (default 5 minutes) of the lifetime is left, retries an
// Unavailable answer every 30 seconds, and returns the error that ended it:
// ctx's, or the Unauthenticated status after which the person must sign in
// again. Run it in a goroutine; renew is [RenewSession] over the caller's
// connection, or a test double.
func KeepRenewed(ctx context.Context, cur Session, lead time.Duration, renew func(ctx context.Context, token string) (Session, error), update func(Session)) error {
	if lead <= 0 {
		lead = 5 * time.Minute
	}
	for {
		wait := time.Until(cur.Expires.Add(-lead))
		for {
			if wait < 0 {
				wait = 0
			}
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
			next, err := renew(ctx, cur.Token)
			if err == nil {
				cur = next
				update(next)
				break
			}
			if status.Code(err) != codes.Unavailable {
				return err
			}
			wait = retryUnavailable
		}
	}
}

// HostChange reads a "sys.host-changed" event: the host role moved from one
// peer to another (peer IDs do not change). ok is false for any other event.
func (e Event) HostChange() (from, to string, ok bool) {
	if e.Kind != "sys.host-changed" {
		return "", "", false
	}
	var h struct{ From, To string }
	if json.Unmarshal(e.Body, &h) != nil || h.To == "" {
		return "", "", false
	}
	return h.From, h.To, true
}

// CoHost reads a "sys.cohost-added" or "sys.cohost-removed" event: peer is the
// one whose co-host powers began or ended. ok is false for any other event.
func (e Event) CoHost() (peer string, added, ok bool) {
	if e.Kind != "sys.cohost-added" && e.Kind != "sys.cohost-removed" {
		return "", false, false
	}
	var b struct{ Peer string }
	if json.Unmarshal(e.Body, &b) != nil || b.Peer == "" {
		return "", false, false
	}
	return b.Peer, e.Kind == "sys.cohost-added", true
}

// Room is a peer's membership of a room.
type Room struct {
	ID      string
	Peer    string
	Host    string // the host's peer ID when the room was entered ("host" for the first one): see CurrentHost
	Expires time.Time

	host   string // the current host's peer ID; guarded by mu
	cohost bool   // this peer is a co-host; guarded by mu

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
	return open(cc, rpc, resp.GetRoom(), resp.GetPeer(), resp.GetPeer(), resp.GetToken(), resp.GetExpires())
}

// JoinOption adjusts [Join].
type JoinOption func(*joinOpts)

type joinOpts struct{ session string }

// WithSession says who the guest is: a session (or access) token, sent as
// metadata with the knock and checked by turnd. A guest that is signed in and
// becomes the host after a handover has the TURN credentials it hands out
// charged to it and not to the person who opened the room. A token that does
// not verify makes Join fail (Unauthenticated).
func WithSession(token string) JoinOption { return func(o *joinOpts) { o.session = token } }

// Join knocks at a room with its ID and a display name, and blocks until the
// host admits the guest (see the package comment).
func Join(ctx context.Context, base, roomID, name string, opts ...JoinOption) (*Room, error) {
	cc, err := Dial(base, wstransport.ClientConfig{})
	if err != nil {
		return nil, err
	}
	r, err := JoinConn(ctx, cc, roomID, name, opts...)
	if err != nil {
		cc.Close()
		return nil, err
	}
	r.ownsCC = true
	return r, nil
}

// JoinConn is [Join] over an existing connection, which the caller closes.
func JoinConn(ctx context.Context, cc *grpc.ClientConn, roomID, name string, opts ...JoinOption) (*Room, error) {
	if !validID(roomID) {
		return nil, errors.New("rendezvous: malformed room ID")
	}
	var o joinOpts
	for _, f := range opts {
		f(&o)
	}
	rpc := turnv1.NewTurndClient(cc)
	jctx := ctx
	if o.session != "" {
		jctx = metadata.AppendToOutgoingContext(ctx, "x-turn-session", o.session)
	}
	resp, err := rpc.JoinRoom(jctx, &turnv1.JoinRoomRequest{Room: roomID, Name: name})
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

// Reclaim is how a person who was the host comes back (a reload, a new
// network, a crash), with a session token: while the grace period lasts, or
// while no one else has been promoted, they are the host again, with a new
// token; after a handover they are an admitted guest of the new host, with the
// peer ID they had. [Room.IsHost] tells which. Unauthenticated: the token is
// not a session; PermissionDenied: this person was never the host of the room.
func Reclaim(ctx context.Context, base, roomID, sessionToken string) (*Room, error) {
	cc, err := Dial(base, wstransport.ClientConfig{})
	if err != nil {
		return nil, err
	}
	r, err := ReclaimConn(ctx, cc, roomID, sessionToken)
	if err != nil {
		cc.Close()
		return nil, err
	}
	r.ownsCC = true
	return r, nil
}

// ReclaimConn is [Reclaim] over an existing connection, which the caller closes.
func ReclaimConn(ctx context.Context, cc *grpc.ClientConn, roomID, sessionToken string) (*Room, error) {
	if !validID(roomID) {
		return nil, errors.New("rendezvous: malformed room ID")
	}
	rpc := turnv1.NewTurndClient(cc)
	resp, err := rpc.Reclaim(withToken(ctx, sessionToken), &turnv1.ReclaimRequest{Room: roomID})
	if err != nil {
		return nil, err
	}
	return open(cc, rpc, resp.GetRoom(), resp.GetPeer(), resp.GetHostPeer(), resp.GetToken(), resp.GetExpires())
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
	r := &Room{ID: room, Peer: peer, Host: host, host: host, Expires: time.Unix(expires, 0), cc: cc, rpc: rpc, token: token,
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
		if _, to, ok := ev.HostChange(); ok {
			r.mu.Lock()
			r.host = to // before the event reaches the caller: IsHost is right when it reads it
			r.mu.Unlock()
		}
		if p, added, ok := ev.CoHost(); ok && p == r.Peer {
			r.mu.Lock()
			r.cohost = added
			r.mu.Unlock()
		}
		if _, to, ok := ev.HostChange(); ok && to == r.Peer {
			r.mu.Lock()
			r.cohost = false // the host's powers contain a co-host's
			r.mu.Unlock()
		}
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

// IsHost reports whether this peer is the room's host now: true for the one
// that created it, and for a guest from the moment it receives the
// "sys.host-changed" that names it (it then has the powers of the host: Admit,
// Deny, Close, Credentials for the others).
func (r *Room) IsHost() bool { return r.CurrentHost() == r.Peer }

// CurrentHost is the peer ID of the host as of the last "sys.host-changed" this
// room has read. Messages to "host" go to it whoever it is.
func (r *Room) CurrentHost() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.host
}

// IsCoHost reports whether this peer is a co-host now (appointed by the host:
// it may Admit, Deny and Close, and hears the knocks too), as of the last
// "sys.cohost-added" or "sys.cohost-removed" this room has read.
func (r *Room) IsCoHost() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cohost
}

// AppointCoHost lets an admitted guest admit, deny and close beside the host;
// RevokeCoHost takes it back at once (host only). There is still one host.
func (r *Room) AppointCoHost(ctx context.Context, peer string) error {
	_, err := r.rpc.AppointCoHost(r.auth(ctx), &turnv1.CoHostRequest{Room: r.ID, Peer: peer})
	return err
}

// RevokeCoHost: see [Room.AppointCoHost].
func (r *Room) RevokeCoHost(ctx context.Context, peer string) error {
	_, err := r.rpc.RevokeCoHost(r.auth(ctx), &turnv1.CoHostRequest{Room: r.ID, Peer: peer})
	return err
}

// HandOver gives the host role to an admitted guest that is connected (host
// only). This peer stops being the host: its token is dead, its stream ends
// after the "sys.host-changed" that tells everyone, and [Reclaim] brings the
// person back as a guest.
func (r *Room) HandOver(ctx context.Context, to string) error {
	_, err := r.rpc.HandOver(r.auth(ctx), &turnv1.HandOverRequest{Room: r.ID, To: to})
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

// CloseRoom ends the room for everyone (host or co-host).
func (r *Room) CloseRoom(ctx context.Context) error {
	_, err := r.rpc.CloseRoom(r.auth(ctx), &turnv1.RoomRef{Room: r.ID})
	return err
}

// Close leaves the room (the host's leaving closes it) and releases the
// connection if the room dialed it.
func (r *Room) Close(ctx context.Context) error {
	var err error
	if r.IsHost() { // a co-host's Close only leaves; it ends the room with CloseRoom
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
