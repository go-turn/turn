// Package rendezvous is a signalling relay for WebRTC peers, as a gRPC service
// (turn.v1.Turnd, proto/turn/v1/turnd.proto). A logged-in host opens a room
// (CreateRoom) and shares its 128-bit random ID; a guest knocks with it
// (JoinRoom) and is PENDING until the host admits it. The room is ONE
// bidirectional stream (Room): events down, messages up, routed host to guest
// and guest to host. An admitted peer can get TURN credentials that expire with
// the room, charged to the host's subject.
//
// A leaked room link therefore lets a stranger knock, not enter: a pending guest
// can receive and nothing else, it cannot send and it cannot spend the host's
// TURN quota.
//
// Every resource is bounded (see [Limits]) and every refusal is tested as a gRPC
// status code. A message that breaks the protocol (too large, a spoofed "from",
// a bad kind, a pending sender, guest to guest) ends the sender's stream with
// that status, which for a guest is leaving and for the host closes the room.
// A message that fails for what the OTHER peer is (gone, queue full) leaves the
// stream open and comes back as a sys.error event, "<Code>: <reason>".
package rendezvous

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-turn/turn/creds"
	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// HostID is the peer ID of a room's host.
const HostID = "host"

// RoomMetadata is the metadata key naming the room on the Room stream.
const RoomMetadata = "x-turn-room"

// MaxNameLen bounds a guest's display name, in characters.
const MaxNameLen = 64

// Limits bounds what a client can make the server hold. Zero fields take the
// default shown.
type Limits struct {
	// MaxMessageBytes bounds a message body (default 16 KiB). The handshake blob
	// of the playground is an SDP description with its ICE candidates, a few KiB.
	MaxMessageBytes int
	// MaxQueue bounds the events waiting for one peer (default 64).
	MaxQueue int
	// MaxGuests bounds the guests ever ADMITTED to one room (default 8).
	MaxGuests int
	// MaxPending bounds the guests waiting for the host's decision in one room
	// (default 8); PendingTTL is how long one may wait (default 2 minutes).
	MaxPending int
	PendingTTL time.Duration
	// MaxRoomsPerSubject bounds the live rooms of one subject (default 4).
	MaxRoomsPerSubject int
	// MaxRooms bounds the live rooms of the server (default 1024).
	MaxRooms int
	// RoomTTL is a room's whole life (default 1 hour).
	RoomTTL time.Duration
	// MaxCredsPerRoom bounds the credential requests of one room (default 64).
	MaxCredsPerRoom int
}

func (l *Limits) defaults() {
	def := func(p *int, v int) {
		if *p <= 0 {
			*p = v
		}
	}
	def(&l.MaxMessageBytes, 16<<10)
	def(&l.MaxQueue, 64)
	def(&l.MaxGuests, 8)
	def(&l.MaxPending, 8)
	def(&l.MaxRoomsPerSubject, 4)
	def(&l.MaxRooms, 1024)
	def(&l.MaxCredsPerRoom, 64)
	if l.PendingTTL <= 0 {
		l.PendingTTL = 2 * time.Minute
	}
	if l.RoomTTL <= 0 {
		l.RoomTTL = time.Hour
	}
}

// Config configures [New].
type Config struct {
	// Auth returns the subject of a session or access token (host operations).
	Auth func(ctx context.Context, token string) (subject string, err error)
	// Renew trades a session token (valid, or expired within a grace it
	// enforces) for a new one: the RenewSession call. It returns
	// [ErrSessionEnded] when the session cannot be renewed (the person signs in
	// again) and [ErrSessionUnavailable] when the identity provider could not be
	// asked (the session is intact). Nil: RenewSession is UNIMPLEMENTED.
	Renew func(ctx context.Context, token string) (token2 string, expiry time.Time, err error)
	// Keyring signs the TURN credentials.
	Keyring *creds.Keyring
	// STUN and TURN are the URLs advertised in credential responses.
	STUN, TURN []string
	Limits     Limits
	// CredTTL is the lifetime of host credentials (default 1 hour); a guest's
	// never outlive the room.
	CredTTL time.Duration
	Now     func() time.Time
	// Observer, when set, is told the outcome of every RPC (see Observer).
	Observer Observer
}

// Observer is told how each RPC ended. It never receives a token, a room ID, a
// peer ID, a name or a subject: only the action and the outcome, so an
// implementation can export both as they are. A nil Observer costs nothing.
type Observer interface {
	// Event reports one RPC. action is one of "credentials_host",
	// "credentials_room", "create_room", "knock", "admit", "deny",
	// "close_room", "renew_session" or "stream"; outcome is "ok" or the lower-case gRPC code
	// name of the refusal ("unauthenticated", "not_found", "resource_exhausted",
	// "permission_denied", "failed_precondition", "invalid_argument",
	// "unavailable", "already_exists"...). ctx is the RPC's context, so an
	// implementation can annotate the span in it.
	Event(ctx context.Context, action, outcome string)
}

// Counts is the live state, for gauges.
type Counts struct {
	Rooms   int // live rooms
	Pending int // guests waiting to be admitted
	Guests  int // admitted guests
}

// Counts returns the live rooms, the guests waiting and the guests admitted.
func (s *Server) Counts() Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := Counts{Rooms: len(s.rooms)}
	for _, rm := range s.rooms {
		for id, p := range rm.peers {
			switch {
			case p.pending:
				c.Pending++
			case id != HostID:
				c.Guests++
			}
		}
	}
	return c
}

func (s *Server) seen(ctx context.Context, action string, err error) {
	if s.cfg.Observer == nil {
		return
	}
	out := "ok"
	if err != nil {
		out = snake(status.Code(err).String())
	}
	s.cfg.Observer.Event(ctx, action, out)
}

// snake turns a gRPC code name ("ResourceExhausted") into "resource_exhausted".
func snake(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if i > 0 {
				b = append(b, '_')
			}
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	return string(b)
}

// Server is the rendezvous. Build it with [New] and [Server.Register] it.
type Server struct {
	turnv1.UnimplementedTurndServer
	cfg Config

	mu    sync.Mutex
	rooms map[string]*room
}

type room struct {
	id       string
	subject  string
	expires  time.Time
	closed   chan struct{}
	isClosed bool
	peers    map[string]*peer
	admitted int // guests ever admitted
	nextID   int // peer IDs handed out
	creds    int
	seq      uint64
}

type peer struct {
	id        string
	token     string
	name      string
	pending   bool // knocked, not yet admitted
	since     time.Time
	queue     []*turnv1.Envelope
	notify    chan struct{}
	done      chan struct{} // closed when the peer is removed: its stream drains and ends
	streaming bool
}

// New validates cfg.
func New(cfg Config) (*Server, error) {
	if cfg.Auth == nil || cfg.Keyring == nil {
		return nil, errors.New("rendezvous: Auth and Keyring are required")
	}
	cfg.Limits.defaults()
	if cfg.CredTTL <= 0 {
		cfg.CredTTL = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Server{cfg: cfg, rooms: map[string]*room{}}, nil
}

// Register adds the service to a gRPC server. Give that server
// grpc.MaxRecvMsgSize of at least [Server.MaxRecvMsgSize].
func (s *Server) Register(gs grpc.ServiceRegistrar) { turnv1.RegisterTurndServer(gs, s) }

// MaxRecvMsgSize is the gRPC receive bound that fits a message at its limit.
func (s *Server) MaxRecvMsgSize() int { return s.cfg.Limits.MaxMessageBytes + 1024 }

func (s *Server) now() time.Time { return s.cfg.Now() }

// Sweep closes the rooms whose time is over and drops the guests whose wait is.
func (s *Server) Sweep() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.rooms {
		if !r.expires.After(now) {
			s.closeLocked(r)
			delete(s.rooms, id)
			continue
		}
		s.expirePendingLocked(r, now)
	}
}

func (s *Server) closeLocked(r *room) {
	if !r.isClosed {
		r.isClosed = true
		close(r.closed)
	}
}

// Run sweeps expired rooms every interval until ctx ends.
func (s *Server) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep()
		}
	}
}

// Rooms is the number of live rooms.
func (s *Server) Rooms() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rooms)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return hex.EncodeToString(b)
}

// bearer reads the token of the "authorization: Bearer ..." metadata.
func bearer(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	v := md.Get("authorization")
	if len(v) != 1 {
		return ""
	}
	h := v[0]
	// 8 KiB: an issuer's access token (a signed JWT) is long; go-authn/oidc
	// bounds the token itself at 16 KiB and ours are far shorter.
	if len(h) < 8 || len(h) > 8<<10 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return h[7:]
}

var errUnauth = status.Error(codes.Unauthenticated, "unauthorized")

// ErrSessionEnded and ErrSessionUnavailable are what Config.Renew answers.
var (
	ErrSessionEnded       = errors.New("rendezvous: session cannot be renewed")
	ErrSessionUnavailable = errors.New("rendezvous: identity provider unavailable")
)

// RenewSession implements turn.v1.Turnd.
func (s *Server) RenewSession(ctx context.Context, _ *turnv1.RenewSessionRequest) (_ *turnv1.RenewSessionResponse, err error) {
	defer func() { s.seen(ctx, "renew_session", err) }()
	if s.cfg.Renew == nil {
		return nil, status.Error(codes.Unimplemented, "session renewal is off")
	}
	tok := bearer(ctx)
	if tok == "" {
		return nil, errUnauth
	}
	nt, exp, err := s.cfg.Renew(ctx, tok) // err is the named result: the deferred observer reads it
	switch {
	case err == nil && nt != "":
		return &turnv1.RenewSessionResponse{Token: nt, Expires: exp.Unix()}, nil
	case errors.Is(err, ErrSessionUnavailable):
		return nil, status.Error(codes.Unavailable, "identity provider unavailable, retry")
	default:
		return nil, errUnauth
	}
}

func (s *Server) subject(ctx context.Context) (string, error) {
	tok := bearer(ctx)
	if tok == "" {
		return "", errUnauth
	}
	sub, err := s.cfg.Auth(ctx, tok)
	if err != nil || sub == "" {
		return "", errUnauth
	}
	return sub, nil
}

func (s *Server) mintResponse(subject string, expiry time.Time) *turnv1.IceServers {
	now := s.now()
	u, p := s.cfg.Keyring.Mint(subject, expiry)
	r := creds.NewResponse(s.cfg.STUN, s.cfg.TURN, u, p, expiry, now)
	out := &turnv1.IceServers{Ttl: int32(r.TTL)}
	for _, is := range r.ICEServers {
		out.IceServers = append(out.IceServers, &turnv1.IceServer{Urls: is.URLs, Username: is.Username, Credential: is.Credential})
	}
	return out
}

// Credentials implements turn.v1.Turnd.
func (s *Server) Credentials(ctx context.Context, _ *turnv1.CredentialsRequest) (_ *turnv1.IceServers, err error) {
	defer func() { s.seen(ctx, "credentials_host", err) }()
	sub, err := s.subject(ctx)
	if err != nil {
		return nil, err
	}
	return s.mintResponse(sub, s.now().Add(s.cfg.CredTTL)), nil
}

func newPeer(id string) *peer {
	return &peer{id: id, token: randHex(16), notify: make(chan struct{}, 1), done: make(chan struct{})}
}

// CreateRoom implements turn.v1.Turnd.
func (s *Server) CreateRoom(ctx context.Context, _ *turnv1.CreateRoomRequest) (_ *turnv1.CreateRoomResponse, err error) {
	defer func() { s.seen(ctx, "create_room", err) }()
	sub, err := s.subject(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.rooms {
		if !r.expires.After(now) {
			s.closeLocked(r)
			delete(s.rooms, id)
		}
	}
	if len(s.rooms) >= s.cfg.Limits.MaxRooms {
		return nil, status.Error(codes.Unavailable, "the server is full")
	}
	n := 0
	for _, rm := range s.rooms {
		if rm.subject == sub {
			n++
		}
	}
	if n >= s.cfg.Limits.MaxRoomsPerSubject {
		return nil, status.Error(codes.ResourceExhausted, "too many rooms")
	}
	rm := &room{id: randHex(16), subject: sub, expires: now.Add(s.cfg.Limits.RoomTTL).Truncate(time.Second),
		closed: make(chan struct{}), peers: map[string]*peer{}}
	host := newPeer(HostID)
	rm.peers[HostID] = host
	s.rooms[rm.id] = rm
	return &turnv1.CreateRoomResponse{Room: rm.id, Peer: HostID, Token: host.token, Expires: rm.expires.Unix()}, nil
}

func validRoomID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// roomLocked finds a live room.
func (s *Server) roomLocked(id string) *room {
	if !validRoomID(id) {
		return nil
	}
	rm := s.rooms[id]
	if rm == nil {
		return nil
	}
	now := s.now()
	if !rm.expires.After(now) {
		s.closeLocked(rm)
		delete(s.rooms, id)
		return nil
	}
	s.expirePendingLocked(rm, now)
	return rm
}

var errNoRoom = status.Error(codes.NotFound, "no such room")

func (rm *room) push(p *peer, e *turnv1.Envelope, limit int, force bool) bool {
	if !force && len(p.queue) >= limit {
		return false
	}
	rm.seq++
	e.Seq = rm.seq
	p.queue = append(p.queue, e)
	select {
	case p.notify <- struct{}{}:
	default:
	}
	return true
}

func sys(from, to, kind, body string) *turnv1.Envelope {
	return &turnv1.Envelope{From: from, To: to, Kind: kind, Body: []byte(body)}
}

// cleanName trims a display name and refuses one that is too long, not UTF-8
// or holds a control character (Unicode Cc, which includes newlines), a format
// character (Cf, which includes bidi overrides) or a line separator.
func cleanName(n string) (string, bool) {
	n = strings.TrimSpace(n)
	if !utf8.ValidString(n) || utf8.RuneCountInString(n) > MaxNameLen {
		return "", false
	}
	for _, r := range n {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return "", false
		}
	}
	return n, true
}

// removeLocked takes p out of the room: it gets final (if any), its token stops
// working, and its stream drains and ends.
func (rm *room) removeLocked(p *peer, final *turnv1.Envelope) {
	if final != nil {
		rm.push(p, final, 0, true)
	}
	delete(rm.peers, p.id)
	close(p.done)
}

// expirePendingLocked removes guests that waited longer than the pending TTL.
func (s *Server) expirePendingLocked(rm *room, now time.Time) {
	for _, p := range rm.peers {
		if p.pending && !p.since.Add(s.cfg.Limits.PendingTTL).After(now) {
			rm.removeLocked(p, sys(HostID, p.id, "sys.denied", "expired"))
			rm.push(rm.peers[HostID], sys(p.id, HostID, "sys.leave", "expired"), 0, true)
		}
	}
}

// JoinRoom implements turn.v1.Turnd.
func (s *Server) JoinRoom(ctx context.Context, req *turnv1.JoinRoomRequest) (_ *turnv1.JoinRoomResponse, err error) {
	defer func() { s.seen(ctx, "knock", err) }()
	name, ok := cleanName(req.GetName())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "bad name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rm := s.roomLocked(req.GetRoom())
	if rm == nil {
		return nil, errNoRoom
	}
	pending := 0
	for _, p := range rm.peers {
		if p.pending {
			pending++
		}
	}
	if pending >= s.cfg.Limits.MaxPending {
		return nil, status.Error(codes.ResourceExhausted, "too many guests waiting")
	}
	rm.nextID++
	g := newPeer("g" + strconv.Itoa(rm.nextID))
	g.pending, g.name, g.since = true, name, s.now()
	rm.peers[g.id] = g
	rm.push(rm.peers[HostID], sys(g.id, HostID, "sys.knock", name), 0, true)
	return &turnv1.JoinRoomResponse{Room: rm.id, Peer: g.id, Host: HostID, Token: g.token, Expires: rm.expires.Unix(), Pending: true}, nil
}

// peerLocked authenticates a token as a peer of the room.
func (s *Server) peerLocked(roomID, tok string) (*room, *peer, error) {
	rm := s.roomLocked(roomID)
	if rm == nil {
		return nil, nil, errNoRoom
	}
	var found *peer
	for _, p := range rm.peers { // every peer is compared: no early exit on the first match
		if subtle.ConstantTimeCompare([]byte(p.token), []byte(tok)) == 1 && tok != "" {
			found = p
		}
	}
	if found == nil {
		return nil, nil, errUnauth
	}
	return rm, found, nil
}

// hostLocked authenticates the host.
func (s *Server) hostLocked(ctx context.Context, roomID string) (*room, error) {
	rm, p, err := s.peerLocked(roomID, bearer(ctx))
	if err != nil {
		return nil, err
	}
	if p.id != HostID {
		return nil, status.Error(codes.PermissionDenied, "only the host can do this")
	}
	return rm, nil
}

func (s *Server) decision(ctx context.Context, req *turnv1.DecideRequest) (*room, *peer, error) {
	if req.GetPeer() == "" || req.GetPeer() == HostID {
		return nil, nil, status.Error(codes.InvalidArgument, "bad peer")
	}
	rm, err := s.hostLocked(ctx, req.GetRoom())
	if err != nil {
		return nil, nil, err
	}
	g := rm.peers[req.GetPeer()]
	if g == nil {
		return nil, nil, status.Error(codes.NotFound, "no such peer")
	}
	return rm, g, nil
}

// Admit implements turn.v1.Turnd.
func (s *Server) Admit(ctx context.Context, req *turnv1.DecideRequest) (_ *turnv1.Ack, err error) {
	defer func() { s.seen(ctx, "admit", err) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	rm, g, err := s.decision(ctx, req)
	if err != nil {
		return nil, err
	}
	if !g.pending {
		return nil, status.Error(codes.FailedPrecondition, "already admitted")
	}
	if rm.admitted >= s.cfg.Limits.MaxGuests {
		return nil, status.Error(codes.ResourceExhausted, "the room is full")
	}
	rm.admitted++
	g.pending = false
	rm.push(g, sys(HostID, g.id, "sys.admitted", ""), 0, true)
	rm.push(rm.peers[HostID], sys(g.id, HostID, "sys.join", g.name), 0, true)
	return &turnv1.Ack{}, nil
}

// Deny implements turn.v1.Turnd: it refuses a waiting guest, or removes an
// admitted one. Its token is dead.
func (s *Server) Deny(ctx context.Context, req *turnv1.DecideRequest) (_ *turnv1.Ack, err error) {
	defer func() { s.seen(ctx, "deny", err) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	rm, g, err := s.decision(ctx, req)
	if err != nil {
		return nil, err
	}
	if !g.pending {
		rm.push(rm.peers[HostID], sys(g.id, HostID, "sys.leave", "removed"), 0, true)
	}
	rm.removeLocked(g, sys(HostID, g.id, "sys.denied", ""))
	return &turnv1.Ack{}, nil
}

// RoomCredentials implements turn.v1.Turnd.
func (s *Server) RoomCredentials(ctx context.Context, req *turnv1.RoomRef) (_ *turnv1.IceServers, err error) {
	defer func() { s.seen(ctx, "credentials_room", err) }()
	s.mu.Lock()
	rm, p, err := s.peerLocked(req.GetRoom(), bearer(ctx))
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if p.pending {
		s.mu.Unlock()
		return nil, status.Error(codes.PermissionDenied, "not admitted yet")
	}
	if rm.creds >= s.cfg.Limits.MaxCredsPerRoom {
		s.mu.Unlock()
		return nil, status.Error(codes.ResourceExhausted, "too many credential requests for this room")
	}
	rm.creds++
	exp, sub := rm.expires, rm.subject
	s.mu.Unlock()
	if e := s.now().Add(s.cfg.CredTTL); e.Before(exp) {
		exp = e
	}
	return s.mintResponse(sub, exp), nil
}

// CloseRoom implements turn.v1.Turnd.
func (s *Server) CloseRoom(ctx context.Context, req *turnv1.RoomRef) (_ *turnv1.Ack, err error) {
	defer func() { s.seen(ctx, "close_room", err) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	rm, err := s.hostLocked(ctx, req.GetRoom())
	if err != nil {
		return nil, err
	}
	s.closeLocked(rm)
	delete(s.rooms, rm.id)
	return &turnv1.Ack{}, nil
}

func validKind(k string) bool {
	if k == "" || len(k) > 32 || strings.HasPrefix(k, "sys.") {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// route validates and delivers one message from p; the error is the status the
// sender's stream ends with.
func (s *Server) route(rm *room, from *peer, m *turnv1.Envelope) error {
	lim := s.cfg.Limits
	if len(m.GetBody()) > lim.MaxMessageBytes {
		return status.Error(codes.ResourceExhausted, "message too large")
	}
	if m.GetFrom() != from.id {
		return status.Error(codes.PermissionDenied, "from is not you")
	}
	if !validKind(m.GetKind()) {
		return status.Error(codes.InvalidArgument, "bad kind")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rm.isClosed {
		return status.Error(codes.NotFound, "room closed")
	}
	if from.pending {
		return status.Error(codes.PermissionDenied, "not admitted yet")
	}
	// Routing is host to guest and guest to host, never guest to guest.
	if from.id != HostID && m.GetTo() != HostID {
		return status.Error(codes.PermissionDenied, "guests talk to the host")
	}
	// What depends on the other peer's state is not the sender's fault (the
	// guest may have just left), so it does not end the stream: the sender gets
	// a sys.error event carrying the code and the reason.
	dst := rm.peers[m.GetTo()]
	if dst == nil || dst == from || dst.pending {
		rm.push(from, sysError(from.id, codes.NotFound, "no such peer"), 0, true)
		return nil
	}
	if !rm.push(dst, &turnv1.Envelope{From: from.id, To: dst.id, Kind: m.GetKind(), Body: m.GetBody()}, lim.MaxQueue, false) {
		rm.push(from, sysError(from.id, codes.ResourceExhausted, "the peer's queue is full"), 0, true)
	}
	return nil
}

// sysError is the event for a refusal that leaves the stream open: the body is
// "<Code>: <reason>", with the gRPC code's name (codes.Code.String).
func sysError(to string, c codes.Code, reason string) *turnv1.Envelope {
	return sys(HostID, to, "sys.error", c.String()+": "+reason)
}

// leave is what ending a peer's stream means: a guest leaves, the host's
// leaving closes the room.
func (s *Server) leave(rm *room, p *peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rm.peers[p.id] != p {
		return // already removed (denied, expired, room closed)
	}
	if p.id == HostID {
		s.closeLocked(rm)
		delete(s.rooms, rm.id)
		return
	}
	rm.removeLocked(p, nil)
	rm.push(rm.peers[HostID], sys(p.id, HostID, "sys.leave", ""), 0, true)
}

// Room implements turn.v1.Turnd.
func (s *Server) Room(stream grpc.BidiStreamingServer[turnv1.Envelope, turnv1.Envelope]) error {
	ctx := stream.Context()
	var roomID string
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(RoomMetadata); len(v) == 1 {
			roomID = v[0]
		}
	}
	s.mu.Lock()
	rm, p, err := s.peerLocked(roomID, bearer(ctx))
	if err == nil && p.streaming {
		err = status.Error(codes.AlreadyExists, "this peer is already streaming")
	}
	if err != nil {
		s.mu.Unlock()
		s.seen(ctx, "stream", err)
		return err
	}
	p.streaming = true
	s.mu.Unlock()
	s.seen(ctx, "stream", nil)
	defer func() {
		s.mu.Lock()
		p.streaming = false
		s.mu.Unlock()
		s.leave(rm, p)
	}()

	sendDone := make(chan error, 1)
	go func() { sendDone <- s.sendLoop(ctx, stream, rm, p) }()
	recvDone := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				recvDone <- err
				return
			}
			if err := s.route(rm, p, m); err != nil {
				recvDone <- err
				return
			}
		}
	}()
	select {
	case err := <-sendDone:
		return err
	case err := <-recvDone:
		return err
	}
}

func (s *Server) sendLoop(ctx context.Context, stream grpc.BidiStreamingServer[turnv1.Envelope, turnv1.Envelope], rm *room, p *peer) error {
	expiry := time.NewTimer(time.Until(rm.expires))
	defer expiry.Stop()
	removed := false
	for {
		for {
			s.mu.Lock()
			var e *turnv1.Envelope
			if len(p.queue) > 0 {
				e = p.queue[0]
				p.queue = p.queue[1:]
			}
			s.mu.Unlock()
			if e == nil {
				break
			}
			if err := stream.Send(e); err != nil {
				return err
			}
		}
		if removed {
			return nil // the peer was removed and its last events are out
		}
		select {
		case <-p.notify:
		case <-p.done:
			removed = true // loop once more to flush what was queued before removal
		case <-rm.closed:
			_ = stream.Send(sys(HostID, p.id, "sys.closed", ""))
			return nil
		case <-expiry.C:
			_ = stream.Send(sys(HostID, p.id, "sys.closed", ""))
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}
