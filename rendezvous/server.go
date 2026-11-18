// Package rendezvous is a signalling relay for WebRTC peers, as a gRPC service
// (turn.v1.Turnd, proto/turn/v1/turnd.proto). A logged-in host opens a room
// (CreateRoom) and shares its 128-bit random ID; a guest knocks with it
// (JoinRoom) and is PENDING until the host admits it. The room is ONE
// bidirectional stream (Room): events down, messages up, routed host to guest
// and guest to host. An admitted peer can get TURN credentials that expire with
// the room, charged to the host's subject.
//
// The room outlives its host: when the host's stream ends it waits
// [Limits.HostGrace] for the same person to come back ([Server.Reclaim]), then
// promotes the earliest-admitted guest still connected, or does as the host says
// ([Server.HandOver]). Peer IDs never change; everyone gets sys.host-changed.
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
	"encoding/json"
	"errors"
	"io"
	"sort"
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

// SessionMetadata is the optional metadata key of JoinRoom (and Reclaim's
// bearer is the same kind of token) carrying a session or access token: who
// the guest is, for the day it becomes the host.
const SessionMetadata = "x-turn-session"

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
	// HostGrace is how long a room outlives its host's stream (default 2
	// minutes): the host that comes back as the same person within it keeps the
	// role, after it the earliest-admitted connected guest is promoted (see
	// [Server.HandOver]). Negative turns this off: the host's stream ending then
	// closes the room, as it did before v0.7.
	HostGrace time.Duration
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
	if l.HostGrace == 0 {
		l.HostGrace = 2 * time.Minute
	}
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
	// "close_room", "hand_over", "appoint_cohost", "revoke_cohost", "reclaim", "renew_session" or "stream", plus two
	// that no RPC carries: "host_lost" (a host's stream ended, the grace period
	// starts) and "promote" (the grace period ended: "ok" when a guest took the
	// role, "failed_precondition" when none could and the room closed; an
	// explicit hand over is "hand_over"); outcome is "ok" or the lower-case gRPC code
	// name of the refusal ("unauthenticated", "not_found", "resource_exhausted",
	// "permission_denied", "failed_precondition", "invalid_argument",
	// "unavailable", "already_exists"...). ctx is the RPC's context, so an
	// implementation can annotate the span in it.
	// The ctx of the two room-state actions is context.Background(). Event may
	// be called while no server lock is held, but must not block for long.
	Event(ctx context.Context, action, outcome string)
}

type note struct{ action, outcome string }

// noteLocked records what happened with no RPC to carry it (the grace period
// ran out, a timer fired); seen flushes it, outside the lock.
func (s *Server) noteLocked(action, outcome string) {
	if s.cfg.Observer != nil {
		s.notes = append(s.notes, note{action, outcome})
	}
}

func (s *Server) flushNotes(ctx context.Context) {
	if s.cfg.Observer == nil {
		return
	}
	s.mu.Lock()
	ns := s.notes
	s.notes = nil
	s.mu.Unlock()
	for _, n := range ns {
		s.cfg.Observer.Event(context.Background(), n.action, n.outcome)
	}
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
		for _, p := range rm.peers {
			switch {
			case p.pending:
				c.Pending++
			case p != rm.host:
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
	s.flushNotes(ctx)
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
	notes []note
}

type room struct {
	id       string
	subject  string // who opened the room: the TTL's and, without a better one, the credentials' owner
	expires  time.Time
	closed   chan struct{}
	isClosed bool
	peers    map[string]*peer
	admitted int // guests ever admitted
	nextID   int // peer IDs handed out
	creds    int
	seq      uint64

	host     *peer            // the one host: always in peers
	hostGone time.Time        // when its stream ended; zero while it is there
	timer    *time.Timer      // fires the end of the grace period
	former   map[string]*peer // hosts that were handed over, by peer ID: they may come back as guests
	ranks    int              // admission order: the lower, the earlier
	cranks   int              // co-host appointment order
}

type peer struct {
	id        string
	token     string
	name      string
	subject   string // who this peer is, when it presented a session: "" otherwise
	rank      int    // order of (re)admission; the host's is 0
	cohost    bool   // appointed by the host: may admit, deny, close; cohostRank is the order of appointment
	cohostRnk int
	pending   bool // knocked, not yet admitted
	since     time.Time
	queue     []*turnv1.Envelope
	notify    chan struct{}
	done      chan struct{} // closed when the peer is removed: its stream drains and ends
	stopped   bool
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

// Sweep closes the rooms whose time is over, drops the guests whose wait is, and
// ends the host grace periods that are over (a timer does too, so the interval
// of Run is not what bounds a wait).
func (s *Server) Sweep() {
	s.sweep()
	s.flushNotes(context.Background())
}

func (s *Server) sweep() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.rooms {
		if !r.expires.After(now) {
			s.closeLocked(r)
			delete(s.rooms, id)
			continue
		}
		s.settleLocked(r, now)
		if !r.isClosed {
			s.expirePendingLocked(r, now)
		}
	}
}

func (s *Server) closeLocked(r *room) {
	if !r.isClosed {
		r.isClosed = true
		if r.timer != nil {
			r.timer.Stop()
		}
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
		closed: make(chan struct{}), peers: map[string]*peer{}, former: map[string]*peer{}}
	host := newPeer(HostID)
	host.name, host.subject = HostID, sub
	rm.peers[HostID] = host
	rm.host = host
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
	s.settleLocked(rm, now)
	if rm.isClosed {
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
	p.stop()
}

func (p *peer) stop() {
	if !p.stopped {
		p.stopped = true
		close(p.done)
	}
}

// expirePendingLocked removes guests that waited longer than the pending TTL.
func (s *Server) expirePendingLocked(rm *room, now time.Time) {
	for _, p := range rm.peers {
		if p.pending && !p.since.Add(s.cfg.Limits.PendingTTL).After(now) {
			rm.removeLocked(p, sys(HostID, p.id, "sys.denied", "expired"))
			rm.tellHostsLocked(p, "sys.leave", "expired")
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
	// A guest may say who it is (a session token in x-turn-session), so that
	// the credentials it mints as a host after a handover are charged to it. A
	// token that does not verify is refused, not ignored.
	subject := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(SessionMetadata); len(v) > 1 || (len(v) == 1 && (v[0] == "" || len(v[0]) > 8<<10)) {
			return nil, errUnauth
		} else if len(v) == 1 {
			if subject, err = s.cfg.Auth(ctx, v[0]); err != nil || subject == "" {
				return nil, errUnauth
			}
		}
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
	g.pending, g.name, g.since, g.subject = true, name, s.now(), subject
	rm.peers[g.id] = g
	rm.tellHostsLocked(g, "sys.knock", name)
	return &turnv1.JoinRoomResponse{Room: rm.id, Peer: g.id, Host: rm.host.id, Token: g.token, Expires: rm.expires.Unix(), Pending: true}, nil
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

// hostLocked authenticates THE host: what only it may do (hand over, appoint
// and revoke co-hosts).
func (s *Server) hostLocked(ctx context.Context, roomID string) (*room, error) {
	rm, p, err := s.peerLocked(roomID, bearer(ctx))
	if err != nil {
		return nil, err
	}
	if p != rm.host {
		return nil, status.Error(codes.PermissionDenied, "only the host can do this")
	}
	return rm, nil
}

// powerLocked authenticates the host or a co-host: what they share (admit,
// deny, close the room). The peer is returned too.
func (s *Server) powerLocked(ctx context.Context, roomID string) (*room, *peer, error) {
	rm, p, err := s.peerLocked(roomID, bearer(ctx))
	if err != nil {
		return nil, nil, err
	}
	if !rm.hasHostPowers(p) {
		return nil, nil, status.Error(codes.PermissionDenied, "only the host can do this")
	}
	return rm, p, nil
}

func (s *Server) decision(ctx context.Context, req *turnv1.DecideRequest) (*room, *peer, error) {
	if req.GetPeer() == "" {
		return nil, nil, status.Error(codes.InvalidArgument, "bad peer")
	}
	rm, by, err := s.powerLocked(ctx, req.GetRoom())
	if err != nil {
		return nil, nil, err
	}
	g := rm.peers[req.GetPeer()]
	if g == rm.host {
		return nil, nil, status.Error(codes.InvalidArgument, "bad peer")
	}
	if g == nil {
		return nil, nil, status.Error(codes.NotFound, "no such peer")
	}
	// nobody decides about a peer with host powers but the host itself
	if g.cohost && by != rm.host {
		return nil, nil, status.Error(codes.PermissionDenied, "only the host decides about a co-host")
	}
	return rm, g, nil
}

// tellHostsLocked sends one event to the host and every co-host, each addressed
// to itself: whoever may decide must hear the knocks, joins and leaves.
func (rm *room) tellHostsLocked(from *peer, kind, body string) {
	for _, p := range rm.peers {
		if rm.hasHostPowers(p) && p != from {
			rm.push(p, sys(from.id, p.id, kind, body), 0, true)
		}
	}
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
	rm.ranks++
	g.pending, g.rank = false, rm.ranks
	rm.push(g, sys(HostID, g.id, "sys.admitted", ""), 0, true)
	rm.tellHostsLocked(g, "sys.join", g.name)
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
		rm.tellHostsLocked(g, "sys.leave", "removed")
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
	// Charged to the host of the moment when it said who it is (a promoted
	// guest that presented a session), else to who opened the room; a co-host
	// that said who it is pays for itself. The expiry is the room's: neither a
	// handover nor a co-host extends it.
	exp, sub := rm.expires, rm.host.subject
	if p.cohost && p.subject != "" {
		sub = p.subject
	}
	if sub == "" {
		sub = rm.subject
	}
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
	rm, _, err := s.powerLocked(ctx, req.GetRoom())
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
	// "host" as the destination of a guest is the CURRENT host, whoever holds
	// the role (peer IDs do not change in a handover); as the destination of the
	// host it is the peer that is literally called "host" (the first host,
	// back as a guest).
	to := m.GetTo()
	if from != rm.host && (to == HostID || to == rm.host.id) {
		to = rm.host.id
	} else if from != rm.host {
		return status.Error(codes.PermissionDenied, "guests talk to the host")
	}
	// What depends on the other peer's state is not the sender's fault (the
	// guest may have just left), so it does not end the stream: the sender gets
	// a sys.error event carrying the code and the reason.
	dst := rm.peers[to]
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
	if p == rm.host {
		if s.cfg.Limits.HostGrace < 0 {
			s.closeLocked(rm)
			delete(s.rooms, rm.id)
			return
		}
		// The room outlives its host's stream for the grace period. The host
		// peer stays (its token still works: a reopened stream is the host back),
		// events and messages for it queue up.
		rm.hostGone = s.now()
		if rm.timer != nil {
			rm.timer.Stop()
		}
		g := s.cfg.Limits.HostGrace
		rm.timer = time.AfterFunc(g, func() {
			s.mu.Lock()
			s.settleLocked(rm, s.now())
			s.mu.Unlock()
			s.flushNotes(context.Background())
		})
		s.noteLocked("host_lost", "ok")
		return
	}
	rm.removeLocked(p, nil)
	rm.tellHostsLocked(p, "sys.leave", "")
}

// hasHostPowers is the one predicate for "may admit, deny, close the room": the
// active host (rm.host, a peer, never a renamed ID: the host is data on the
// room, not the constant "host") or a co-host the host appointed. There is
// exactly ONE active host, the peer that runs the document's centre; handing
// over, appointing and revoking stay the host's alone.
func (rm *room) hasHostPowers(p *peer) bool { return p == rm.host || p.cohost }

// hostBackLocked ends the grace period: the host has its role.
func (rm *room) hostBackLocked() {
	rm.hostGone = time.Time{}
	if rm.timer != nil {
		rm.timer.Stop()
		rm.timer = nil
	}
}

// settleLocked ends the grace period if it is over: the earliest-admitted
// guest still connected becomes the host, and if there is none the room is
// over (nobody is left to host it).
func (s *Server) settleLocked(rm *room, now time.Time) {
	if rm.isClosed || rm.hostGone.IsZero() || now.Before(rm.hostGone.Add(s.cfg.Limits.HostGrace)) {
		return
	}
	var best *peer
	for _, p := range rm.peers {
		if p.pending || p == rm.host || !p.streaming {
			continue
		}
		// the earliest-APPOINTED co-host first; no co-host connected: the
		// earliest-ADMITTED guest
		if best == nil || better(p, best) {
			best = p
		}
	}
	if best == nil {
		s.noteLocked("promote", "failed_precondition")
		s.closeLocked(rm)
		delete(s.rooms, rm.id)
		return
	}
	s.handOverLocked(rm, best)
	s.noteLocked("promote", "ok")
}

// better reports whether a is to be promoted before b.
func better(a, b *peer) bool {
	if a.cohost != b.cohost {
		return a.cohost
	}
	if a.cohost {
		return a.cohostRnk < b.cohostRnk
	}
	return a.rank < b.rank
}

type hostChange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type cohostEvent struct {
	Peer string `json:"peer"`
}

// AppointCoHost implements turn.v1.Turnd.
func (s *Server) AppointCoHost(ctx context.Context, req *turnv1.CoHostRequest) (_ *turnv1.Ack, err error) {
	defer func() { s.seen(ctx, "appoint_cohost", err) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	rm, err := s.hostLocked(ctx, req.GetRoom())
	if err != nil {
		return nil, err
	}
	g := rm.peers[req.GetPeer()]
	switch {
	case req.GetPeer() == "" || g == rm.host:
		return nil, status.Error(codes.InvalidArgument, "bad peer")
	case g == nil:
		return nil, status.Error(codes.NotFound, "no such peer")
	case g.pending:
		return nil, status.Error(codes.FailedPrecondition, "not admitted yet")
	case g.cohost:
		return nil, status.Error(codes.FailedPrecondition, "already a co-host")
	}
	rm.cranks++
	g.cohost, g.cohostRnk = true, rm.cranks
	rm.tellAllLocked("sys.cohost-added", g.id)
	// a new co-host answers the knocks too: it hears the waiting guests again
	var waiting []*peer
	for _, p := range rm.peers {
		if p.pending {
			waiting = append(waiting, p)
		}
	}
	sort.Slice(waiting, func(i, j int) bool { return waiting[i].since.Before(waiting[j].since) })
	for _, p := range waiting {
		rm.push(g, sys(p.id, g.id, "sys.knock", p.name), 0, true)
	}
	return &turnv1.Ack{}, nil
}

// RevokeCoHost implements turn.v1.Turnd.
func (s *Server) RevokeCoHost(ctx context.Context, req *turnv1.CoHostRequest) (_ *turnv1.Ack, err error) {
	defer func() { s.seen(ctx, "revoke_cohost", err) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	rm, err := s.hostLocked(ctx, req.GetRoom())
	if err != nil {
		return nil, err
	}
	g := rm.peers[req.GetPeer()]
	switch {
	case req.GetPeer() == "" || g == rm.host:
		return nil, status.Error(codes.InvalidArgument, "bad peer")
	case g == nil:
		return nil, status.Error(codes.NotFound, "no such peer")
	case !g.cohost:
		return nil, status.Error(codes.FailedPrecondition, "not a co-host")
	}
	g.cohost = false // the powers go with this call, not with the news
	rm.tellAllLocked("sys.cohost-removed", g.id)
	return &turnv1.Ack{}, nil
}

// tellAllLocked sends a co-host event, body {"peer":id}, to every peer.
func (rm *room) tellAllLocked(kind, id string) {
	body, _ := json.Marshal(cohostEvent{Peer: id})
	for _, p := range rm.peers {
		rm.push(p, sys(HostID, p.id, kind, string(body)), 0, true)
	}
}

// handOverLocked makes to the host: the one place the role moves, under the
// server's lock, so there is exactly one host at any moment.
func (s *Server) handOverLocked(rm *room, to *peer) {
	old := rm.host
	body, _ := json.Marshal(hostChange{From: old.id, To: to.id})
	// What guests sent to the host and the old host never read goes to the new
	// one, in order: nothing is lost in the window. Events (sys.*) are not carried,
	// the new host is told the state again below.
	var carry []*turnv1.Envelope
	for _, e := range old.queue {
		if !strings.HasPrefix(e.GetKind(), "sys.") && e.GetFrom() != to.id {
			carry = append(carry, &turnv1.Envelope{From: e.GetFrom(), To: to.id, Kind: e.GetKind(), Body: e.GetBody()})
		}
	}
	old.queue = nil
	rm.hostBackLocked()
	// The old host leaves the room's peers, its token is dead and its stream (if
	// it is still there) ends after the news. It may come back with Reclaim.
	rm.removeLocked(old, sys(HostID, old.id, "sys.host-changed", string(body)))
	old.token = ""
	rm.former[old.id] = old
	rm.host = to
	to.rank = 0
	to.cohost = false // the host's powers contain a co-host's; sys.host-changed is the news
	for _, p := range rm.peers {
		rm.push(p, sys(HostID, p.id, "sys.host-changed", string(body)), 0, true)
	}
	// Admission survives the handover: the waiting guests knock again, to the
	// new host, and the admitted ones are announced to it.
	var others []*peer
	for _, p := range rm.peers {
		if p != to {
			others = append(others, p)
		}
	}
	sort.Slice(others, func(i, j int) bool {
		a, b := others[i], others[j]
		if a.pending != b.pending {
			return !a.pending // admitted first
		}
		if a.pending {
			return a.since.Before(b.since)
		}
		return a.rank < b.rank
	})
	for _, p := range others {
		if p.pending {
			rm.push(to, sys(p.id, to.id, "sys.knock", p.name), 0, true)
		} else {
			rm.push(to, sys(p.id, to.id, "sys.join", p.name), 0, true)
		}
	}
	for _, e := range carry {
		rm.push(to, e, 0, true)
	}
}

// HandOver implements turn.v1.Turnd.
func (s *Server) HandOver(ctx context.Context, req *turnv1.HandOverRequest) (_ *turnv1.Ack, err error) {
	defer func() { s.seen(ctx, "hand_over", err) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	rm, err := s.hostLocked(ctx, req.GetRoom())
	if err != nil {
		return nil, err
	}
	to := rm.peers[req.GetTo()]
	switch {
	case req.GetTo() == "":
		return nil, status.Error(codes.InvalidArgument, "bad peer")
	case to == rm.host:
		return nil, status.Error(codes.InvalidArgument, "the host cannot hand over to itself")
	case to == nil:
		return nil, status.Error(codes.NotFound, "no such peer")
	case to.pending:
		return nil, status.Error(codes.FailedPrecondition, "not admitted yet")
	case !to.streaming:
		return nil, status.Error(codes.FailedPrecondition, "not connected")
	}
	s.handOverLocked(rm, to)
	return &turnv1.Ack{}, nil
}

// Reclaim implements turn.v1.Turnd.
func (s *Server) Reclaim(ctx context.Context, req *turnv1.ReclaimRequest) (_ *turnv1.ReclaimResponse, err error) {
	defer func() { s.seen(ctx, "reclaim", err) }()
	sub, err := s.subject(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rm := s.roomLocked(req.GetRoom())
	if rm == nil {
		return nil, errNoRoom
	}
	switch old := rm.host; {
	case old.subject == sub:
		// The host's role is still theirs. The peer is replaced, so a stale
		// stream of the old one ends and nothing it had not read is lost.
		np := newPeer(old.id)
		np.name, np.subject, np.queue = old.name, old.subject, old.queue
		old.queue, old.token = nil, ""
		rm.peers[np.id] = np
		rm.host = np
		old.stop()
		rm.hostBackLocked()
		return &turnv1.ReclaimResponse{Room: rm.id, Peer: np.id, Host: true, HostPeer: np.id, Token: np.token, Expires: rm.expires.Unix()}, nil
	default:
		for id, f := range rm.former {
			if f.subject != sub {
				continue
			}
			// A handover happened: the person is an ordinary admitted guest, with
			// the peer ID it had (so whatever is derived from it is unchanged).
			delete(rm.former, id)
			np := newPeer(f.id)
			np.name, np.subject = f.name, f.subject
			rm.ranks++
			np.rank = rm.ranks
			rm.peers[np.id] = np
			rm.push(rm.host, sys(np.id, rm.host.id, "sys.join", np.name), 0, true)
			return &turnv1.ReclaimResponse{Room: rm.id, Peer: np.id, HostPeer: rm.host.id, Token: np.token, Expires: rm.expires.Unix()}, nil
		}
	}
	return nil, status.Error(codes.PermissionDenied, "you were never the host of this room")
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
	if p == rm.host {
		rm.hostBackLocked() // the host's stream is open again within the grace period
	}
	s.mu.Unlock()
	s.seen(ctx, "stream", nil)
	sctx, stop := context.WithCancel(ctx)
	sendDone := make(chan error, 1)
	sent := false
	defer func() {
		// The send loop is over before the peer is marked as gone: it would
		// otherwise race a reopened stream for the same queue.
		stop()
		if !sent {
			// Bounded: a Send blocked on a client that does not read ends only
			// when this handler returns (and then requeues what it held).
			select {
			case <-sendDone:
			case <-time.After(2 * time.Second):
			}
		}
		s.mu.Lock()
		p.streaming = false
		s.mu.Unlock()
		s.leave(rm, p)
		s.flushNotes(ctx)
	}()
	go func() { sendDone <- s.sendLoop(sctx, stream, rm, p) }()
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
		sent = true
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
				// Not delivered: back to the front of the queue (of the peer's
				// current incarnation if Reclaim replaced it), for the next stream.
				s.mu.Lock()
				cur := rm.peers[p.id]
				if cur == nil {
					cur = p
				}
				cur.queue = append([]*turnv1.Envelope{e}, cur.queue...)
				s.mu.Unlock()
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
