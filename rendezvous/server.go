// Package rendezvous is a signalling relay for two or more WebRTC peers, over
// plain HTTP: no WebSocket. A logged-in host opens a room (POST /rooms), shares
// its 128-bit random ID (the capability), and each guest joins with it. Events
// reach a peer as Server-Sent Events; messages go up as POSTs and are routed
// host to guest or guest to host. A guest can also receive TURN credentials
// that expire with the room and are charged to the host's subject.
//
// Every resource is bounded (see [Limits]) and every refusal is tested.
package rendezvous

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/go-turn/turn/creds"
)

// HostID is the peer ID of a room's host.
const HostID = "host"

// Limits bounds what a client can make the server hold. Zero fields take the
// default shown.
type Limits struct {
	// MaxMessageBytes bounds a message body (default 16 KiB). The handshake blob
	// of the playground is an SDP description with its ICE candidates, a few KiB.
	MaxMessageBytes int
	// MaxQueue bounds the events waiting for one peer (default 64).
	MaxQueue int
	// MaxGuests bounds the guests that ever joined one room (default 8).
	MaxGuests int
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
	def(&l.MaxRoomsPerSubject, 4)
	def(&l.MaxRooms, 1024)
	def(&l.MaxCredsPerRoom, 64)
	if l.RoomTTL <= 0 {
		l.RoomTTL = time.Hour
	}
}

// Config configures [New].
type Config struct {
	// Auth returns the subject of a request's bearer session (host operations).
	Auth func(r *http.Request) (subject string, err error)
	// Keyring signs the TURN credentials.
	Keyring *creds.Keyring
	// STUN and TURN are the URLs advertised in credential responses.
	STUN, TURN []string
	// Origins is the exact-origin CORS allowlist.
	Origins []string
	Limits  Limits
	// CredTTL is the lifetime of host credentials (default 1 hour); a guest's
	// never outlive the room.
	CredTTL time.Duration
	Now     func() time.Time
}

// Server is the rendezvous. Build it with [New].
type Server struct {
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
	guests   int // ever joined
	creds    int
	seq      uint64
}

type peer struct {
	id        string
	token     string
	queue     []Event
	notify    chan struct{}
	streaming bool
}

// Event is what a peer receives. System events have a Kind starting "sys."
// (sys.join and sys.leave, From the guest, To the host).
type Event struct {
	Seq  uint64 `json:"seq"`
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
	Body string `json:"body"`
}

// New validates cfg.
func New(cfg Config) (*Server, error) {
	if cfg.Auth == nil || cfg.Keyring == nil {
		return nil, errors.New("rendezvous: Auth and Keyring are required")
	}
	for _, o := range cfg.Origins {
		if o == "" || o == "*" {
			return nil, errors.New("rendezvous: an allowed origin must be exact, never * or empty")
		}
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

func (s *Server) now() time.Time { return s.cfg.Now() }

// Sweep closes the rooms whose time is over.
func (s *Server) Sweep() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
}

func (s *Server) sweepLocked(now time.Time) {
	for id, r := range s.rooms {
		if !r.expires.After(now) {
			s.closeLocked(r)
			delete(s.rooms, id)
		}
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

// Handler is the HTTP API, behind the CORS allowlist.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /credentials", s.hostCredentials)
	mux.HandleFunc("POST /rooms", s.createRoom)
	mux.HandleFunc("POST /rooms/{id}/join", s.join)
	mux.HandleFunc("GET /rooms/{id}/events", s.events)
	mux.HandleFunc("POST /rooms/{id}/messages", s.message)
	mux.HandleFunc("POST /rooms/{id}/credentials", s.guestCredentials)
	mux.HandleFunc("POST /rooms/{id}/leave", s.leave)
	mux.HandleFunc("DELETE /rooms/{id}", s.deleteRoom)
	return s.cors(mux)
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Vary", "Origin")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		if o := r.Header.Get("Origin"); o != "" {
			if !slices.Contains(s.cfg.Origins, o) {
				writeErr(w, http.StatusForbidden, "origin not allowed")
				return
			}
			h.Set("Access-Control-Allow-Origin", o)
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return hex.EncodeToString(b)
}

func (s *Server) subject(w http.ResponseWriter, r *http.Request) (string, bool) {
	sub, err := s.cfg.Auth(r)
	if err != nil || sub == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return "", false
	}
	return sub, true
}

func (s *Server) mintResponse(subject string, expiry time.Time) creds.Response {
	now := s.now()
	u, p := s.cfg.Keyring.Mint(subject, expiry)
	return creds.NewResponse(s.cfg.STUN, s.cfg.TURN, u, p, expiry, now)
}

func (s *Server) hostCredentials(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.subject(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.mintResponse(sub, s.now().Add(s.cfg.CredTTL)))
}

// CreateResponse is the answer to POST /rooms.
type CreateResponse struct {
	Room    string `json:"room"`
	Peer    string `json:"peer"`
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
}

// JoinResponse is the answer to POST /rooms/{id}/join.
type JoinResponse struct {
	Room    string `json:"room"`
	Peer    string `json:"peer"`
	Host    string `json:"host"`
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
}

func newPeer(id string) *peer {
	return &peer{id: id, token: randHex(16), notify: make(chan struct{}, 1)}
}

func (s *Server) createRoom(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.subject(w, r)
	if !ok {
		return
	}
	now := s.now()
	s.mu.Lock()
	s.sweepLocked(now)
	if len(s.rooms) >= s.cfg.Limits.MaxRooms {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusServiceUnavailable, "the server is full")
		return
	}
	n := 0
	for _, rm := range s.rooms {
		if rm.subject == sub {
			n++
		}
	}
	if n >= s.cfg.Limits.MaxRoomsPerSubject {
		s.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "too many rooms")
		return
	}
	rm := &room{id: randHex(16), subject: sub, expires: now.Add(s.cfg.Limits.RoomTTL).Truncate(time.Second),
		closed: make(chan struct{}), peers: map[string]*peer{}}
	host := newPeer(HostID)
	rm.peers[HostID] = host
	s.rooms[rm.id] = rm
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, CreateResponse{Room: rm.id, Peer: HostID, Token: host.token, Expires: rm.expires.Unix()})
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
	if !rm.expires.After(s.now()) {
		s.closeLocked(rm)
		delete(s.rooms, id)
		return nil
	}
	return rm
}

func (rm *room) push(p *peer, e Event, limit int, force bool) bool {
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

func (s *Server) join(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	rm := s.roomLocked(r.PathValue("id"))
	if rm == nil {
		s.mu.Unlock()
		writeErr(w, http.StatusNotFound, "no such room")
		return
	}
	if rm.guests >= s.cfg.Limits.MaxGuests {
		s.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "the room is full")
		return
	}
	rm.guests++
	g := newPeer("g" + strconv.Itoa(rm.guests))
	rm.peers[g.id] = g
	rm.push(rm.peers[HostID], Event{From: g.id, To: HostID, Kind: "sys.join"}, 0, true)
	exp := rm.expires
	id := rm.id
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, JoinResponse{Room: id, Peer: g.id, Host: HostID, Token: g.token, Expires: exp.Unix()})
}

// peerFor authenticates a request as a peer of the room, by its bearer token.
func (s *Server) peerFor(w http.ResponseWriter, r *http.Request) (*room, *peer, bool) {
	tok := bearerToken(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	rm := s.roomLocked(r.PathValue("id"))
	if rm == nil {
		writeErr(w, http.StatusNotFound, "no such room")
		return nil, nil, false
	}
	var found *peer
	for _, p := range rm.peers { // every peer is compared: no early exit on the first match
		if subtle.ConstantTimeCompare([]byte(p.token), []byte(tok)) == 1 && tok != "" {
			found = p
		}
	}
	if found == nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return nil, nil, false
	}
	return rm, found, true
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || len(h) > 200 || !equalFold7(h[:7], "bearer ") {
		return ""
	}
	return h[7:]
}

func equalFold7(a, b string) bool {
	for i := 0; i < 7; i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// MessageRequest is the body of POST /rooms/{id}/messages.
type MessageRequest struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
	Body string `json:"body"`
}

func validKind(k string) bool {
	if k == "" || len(k) > 32 || len(k) >= 4 && k[:4] == "sys." {
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

func (s *Server) message(w http.ResponseWriter, r *http.Request) {
	rm, from, ok := s.peerFor(w, r)
	if !ok {
		return
	}
	lim := s.cfg.Limits
	// The envelope around a body of MaxMessageBytes (JSON escaping can double
	// non-ASCII bytes, so the cap is on the request, and the body is re-checked).
	r.Body = http.MaxBytesReader(w, r.Body, int64(lim.MaxMessageBytes)*6+1024)
	var m MessageRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "message too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "bad message")
		return
	}
	if len(m.Body) > lim.MaxMessageBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "message too large")
		return
	}
	if m.From != from.id {
		writeErr(w, http.StatusForbidden, "from is not you")
		return
	}
	if !validKind(m.Kind) {
		writeErr(w, http.StatusBadRequest, "bad kind")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if rm.isClosed {
		writeErr(w, http.StatusGone, "room closed")
		return
	}
	// Routing is host to guest and guest to host, never guest to guest.
	if from.id != HostID && m.To != HostID {
		writeErr(w, http.StatusForbidden, "guests talk to the host")
		return
	}
	dst := rm.peers[m.To]
	if dst == nil || dst == from {
		writeErr(w, http.StatusNotFound, "no such peer")
		return
	}
	if !rm.push(dst, Event{From: from.id, To: dst.id, Kind: m.Kind, Body: m.Body}, lim.MaxQueue, false) {
		writeErr(w, http.StatusTooManyRequests, "the peer's queue is full")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) guestCredentials(w http.ResponseWriter, r *http.Request) {
	rm, _, ok := s.peerFor(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	if rm.creds >= s.cfg.Limits.MaxCredsPerRoom {
		s.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "too many credential requests for this room")
		return
	}
	rm.creds++
	exp, sub := rm.expires, rm.subject
	s.mu.Unlock()
	now := s.now()
	if e := now.Add(s.cfg.CredTTL); e.Before(exp) {
		exp = e
	}
	writeJSON(w, http.StatusOK, s.mintResponse(sub, exp))
}

func (s *Server) leave(w http.ResponseWriter, r *http.Request) {
	rm, p, ok := s.peerFor(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	if p.id == HostID {
		s.closeLocked(rm)
		delete(s.rooms, rm.id)
	} else {
		delete(rm.peers, p.id)
		rm.push(rm.peers[HostID], Event{From: p.id, To: HostID, Kind: "sys.leave"}, 0, true)
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteRoom(w http.ResponseWriter, r *http.Request) {
	rm, p, ok := s.peerFor(w, r)
	if !ok {
		return
	}
	if p.id != HostID {
		writeErr(w, http.StatusForbidden, "only the host closes a room")
		return
	}
	s.mu.Lock()
	s.closeLocked(rm)
	delete(s.rooms, rm.id)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

const heartbeat = 15 * time.Second

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	rm, p, ok := s.peerFor(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	if p.streaming {
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, "this peer is already streaming")
		return
	}
	p.streaming = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		p.streaming = false
		s.mu.Unlock()
	}()

	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("X-Accel-Buffering", "no")
	extend := func() { _ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second)) }
	write := func(s string) bool {
		extend()
		if _, err := fmt.Fprint(w, s); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	w.WriteHeader(http.StatusOK)
	if !write(": turnd\n\n") {
		return
	}
	hb := time.NewTicker(heartbeat)
	defer hb.Stop()
	expiry := time.NewTimer(time.Until(rm.expires))
	defer expiry.Stop()
	for {
		for {
			s.mu.Lock()
			var e Event
			have := len(p.queue) > 0
			if have {
				e = p.queue[0]
			}
			s.mu.Unlock()
			if !have {
				break
			}
			b, _ := json.Marshal(e)
			if !write("id: " + strconv.FormatUint(e.Seq, 10) + "\nevent: message\ndata: " + string(b) + "\n\n") {
				return
			}
			s.mu.Lock()
			if len(p.queue) > 0 && p.queue[0].Seq == e.Seq {
				p.queue = p.queue[1:]
			}
			s.mu.Unlock()
		}
		select {
		case <-p.notify:
		case <-hb.C:
			if !write(": hb\n\n") {
				return
			}
		case <-rm.closed:
			write("event: closed\ndata: {}\n\n")
			return
		case <-expiry.C:
			write("event: closed\ndata: {}\n\n")
			return
		case <-r.Context().Done():
			return
		}
	}
}
