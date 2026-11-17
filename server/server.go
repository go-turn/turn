package server

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-turn/turn/stun"
)

// ErrClosed is returned by the Serve methods after Close.
var ErrClosed = errors.New("server: closed")

// Server is a TURN server. Create it with New, hand it sockets with
// ServePacketConn, ServeListener and ServeTLS, stop it with Close.
type Server struct {
	cfg    Config
	pol    *policy
	secret [32]byte

	mu      sync.RWMutex
	allocs  map[fiveTuple]*allocation
	perUser map[string]int
	closers map[io.Closer]struct{}
	closed  bool

	conns atomic.Int64
	done  chan struct{}
	wg    sync.WaitGroup

	st counters
}

type counters struct {
	allocated, toPeer, toClient, dropped, binds atomic.Uint64
}

// Stats is a snapshot of the server counters.
type Stats struct {
	Allocations     int    // live allocations
	Allocated       uint64 // allocations ever created
	PacketsToPeer   uint64 // client to peer datagrams relayed
	PacketsToClient uint64 // peer to client datagrams relayed
	Dropped         uint64 // datagrams dropped (no permission, rate cap, bad frame)
	ChannelBinds    uint64 // successful ChannelBind requests
}

// New validates cfg and returns a stopped-until-served Server.
func New(cfg Config) (*Server, error) {
	if err := cfg.withDefaults(); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:     cfg,
		pol:     newPolicy(cfg.AllowPeers, append([]netip.Addr{cfg.RelayIP}, cfg.OwnAddrs...)),
		allocs:  make(map[fiveTuple]*allocation),
		perUser: make(map[string]int),
		closers: make(map[io.Closer]struct{}),
		done:    make(chan struct{}),
	}
	if _, err := rand.Read(s.secret[:]); err != nil {
		return nil, err
	}
	s.wg.Add(1)
	go s.janitor()
	return s, nil
}

// Stats returns the current counters.
func (s *Server) Stats() Stats {
	s.mu.RLock()
	n := len(s.allocs)
	s.mu.RUnlock()
	return Stats{n, s.st.allocated.Load(), s.st.toPeer.Load(), s.st.toClient.Load(), s.st.dropped.Load(), s.st.binds.Load()}
}

// Close stops every listener, connection and allocation and waits for the
// goroutines to end.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	cl := make([]io.Closer, 0, len(s.closers))
	for c := range s.closers {
		cl = append(cl, c)
	}
	as := make([]*allocation, 0, len(s.allocs))
	for _, a := range s.allocs {
		as = append(as, a)
	}
	s.mu.Unlock()
	for _, c := range cl {
		c.Close()
	}
	for _, a := range as {
		s.removeAlloc(a)
	}
	s.wg.Wait()
	return nil
}

func (s *Server) track(c io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.closers[c] = struct{}{}
	return true
}

func (s *Server) untrack(c io.Closer) {
	s.mu.Lock()
	delete(s.closers, c)
	s.mu.Unlock()
}

// transport is how a reply reaches the client.
type transport interface {
	local() netip.AddrPort
	proto() uint8
	isStream() bool
	send(to netip.AddrPort, b []byte) error
}

const (
	protoTCP = 6
	protoUDP = 17
)

type fiveTuple struct {
	client, server netip.AddrPort
	proto          uint8
}

func ap(a netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()) }

type udpTransport struct {
	pc   net.PacketConn
	udp  *net.UDPConn
	addr netip.AddrPort
}

func (t *udpTransport) local() netip.AddrPort { return t.addr }
func (t *udpTransport) proto() uint8          { return protoUDP }
func (t *udpTransport) isStream() bool        { return false }
func (t *udpTransport) send(to netip.AddrPort, b []byte) error {
	if t.udp != nil {
		_, err := t.udp.WriteToUDPAddrPort(b, to)
		return err
	}
	_, err := t.pc.WriteTo(b, net.UDPAddrFromAddrPort(to))
	return err
}

type streamTransport struct {
	conn net.Conn
	mu   sync.Mutex
	addr netip.AddrPort
}

func (t *streamTransport) local() netip.AddrPort { return t.addr }
func (t *streamTransport) proto() uint8          { return protoTCP }
func (t *streamTransport) isStream() bool        { return true }
func (t *streamTransport) send(_ netip.AddrPort, b []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := t.conn.Write(b)
	return err
}

func addrPortOf(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.UDPAddr:
		return ap(v.AddrPort())
	case *net.TCPAddr:
		return ap(v.AddrPort())
	}
	p, _ := netip.ParseAddrPort(a.String())
	return ap(p)
}

// ServePacketConn serves STUN and TURN over the UDP socket pc until it is
// closed. It returns nil when pc is closed by Close.
func (s *Server) ServePacketConn(pc net.PacketConn) error {
	if !s.track(pc) {
		return ErrClosed
	}
	defer s.untrack(pc)
	tr := &udpTransport{pc: pc, addr: addrPortOf(pc.LocalAddr())}
	tr.udp, _ = pc.(*net.UDPConn)
	s.pol.addOwn(tr.addr.Addr())
	buf := make([]byte, 65535)
	failures := 0
	for {
		var from netip.AddrPort
		var n int
		var err error
		if tr.udp != nil {
			n, from, err = tr.udp.ReadFromUDPAddrPort(buf)
			from = ap(from)
		} else {
			var a net.Addr
			n, a, err = pc.ReadFrom(buf)
			if err == nil {
				from = addrPortOf(a)
			}
		}
		if err != nil {
			if s.isDone() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Windows reports ICMP port-unreachable as a read error; skip
			// it, but not forever.
			if failures++; failures >= 100 {
				return err
			}
			continue
		}
		failures = 0
		s.handlePacket(tr, from, buf[:n])
	}
}

func (s *Server) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// ServeListener serves STUN and TURN over TCP connections accepted from ln
// until it is closed. With Config.ProxyProtocolFrom set, connections from the
// listed sources must start with a PROXY protocol header.
func (s *Server) ServeListener(ln net.Listener) error { return s.serveStream(ln, nil) }

// ServeTLS serves TURN over TLS (turns:) on ln with cfg. With
// Config.ProxyProtocolFrom set, a PROXY protocol header from a listed source
// is read before the TLS handshake (it precedes the ClientHello).
func (s *Server) ServeTLS(ln net.Listener, cfg *tls.Config) error {
	if cfg == nil {
		return errors.New("server: ServeTLS needs a tls.Config")
	}
	return s.serveStream(ln, cfg)
}

func (s *Server) serveStream(ln net.Listener, tlsCfg *tls.Config) error {
	if !s.track(ln) {
		return ErrClosed
	}
	defer s.untrack(ln)
	if a := addrPortOf(ln.Addr()); a.IsValid() {
		s.pol.addOwn(a.Addr())
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			if s.isDone() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return err
		}
		if s.conns.Add(1) > int64(s.cfg.MaxConns) {
			s.conns.Add(-1)
			c.Close()
			s.st.dropped.Add(1)
			continue
		}
		if !s.track(c) {
			s.conns.Add(-1)
			c.Close()
			return ErrClosed
		}
		s.wg.Add(1)
		go s.serveConn(c, tlsCfg)
	}
}

// proxyTrusted reports whether a connection from a may carry a PROXY header.
func (s *Server) proxyTrusted(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s.cfg.ProxyProtocolFrom {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s *Server) serveConn(raw net.Conn, tlsCfg *tls.Config) {
	defer s.wg.Done()
	defer s.conns.Add(-1)
	defer s.untrack(raw)
	defer raw.Close()
	remote := addrPortOf(raw.RemoteAddr())
	var c net.Conn = raw
	if s.proxyTrusted(remote.Addr()) {
		// The header is read straight off the socket, before any TLS
		// handshake, under a bounded size and the handshake deadline.
		raw.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
		h, err := readProxyHeader(raw)
		if err != nil {
			s.cfg.Logger.Debug("PROXY header refused", "from", remote, "err", err)
			s.st.dropped.Add(1)
			return
		}
		if !h.Local {
			s.cfg.Logger.Debug("PROXY header", "proxy", remote, "client", h.Src)
			remote = h.Src
		}
	}
	// A header from any other source is not read as one: the bytes reach the
	// STUN framer (or the TLS handshake), which refuses them and closes.
	if tlsCfg != nil {
		c = tls.Server(raw, tlsCfg)
	}
	tr := &streamTransport{conn: c, addr: addrPortOf(raw.LocalAddr())}
	key := fiveTuple{client: remote, server: tr.addr, proto: protoTCP}
	defer func() {
		if a := s.lookup(key); a != nil {
			s.removeAlloc(a)
		}
	}()
	var buf []byte
	for {
		d := s.cfg.HandshakeTimeout
		if s.lookup(key) != nil {
			d = s.cfg.IdleTimeout
		}
		c.SetReadDeadline(time.Now().Add(d))
		var frame []byte
		var err error
		frame, buf, err = stun.ReadFrame(c, buf)
		if err != nil {
			return
		}
		s.handlePacket(tr, remote, frame)
	}
}

func (s *Server) lookup(k fiveTuple) *allocation {
	s.mu.RLock()
	a := s.allocs[k]
	s.mu.RUnlock()
	return a
}

func (s *Server) handlePacket(tr transport, from netip.AddrPort, pkt []byte) {
	switch {
	case stun.IsChannelData(pkt):
		s.handleChannelData(tr, from, pkt)
	case stun.IsMessage(pkt):
		m, err := stun.Decode(pkt)
		if err != nil {
			s.st.dropped.Add(1)
			return
		}
		s.handleSTUN(tr, from, m)
	default:
		s.st.dropped.Add(1)
	}
}

func (s *Server) handleChannelData(tr transport, from netip.AddrPort, pkt []byte) {
	a := s.lookup(fiveTuple{from, tr.local(), tr.proto()})
	if a == nil {
		s.st.dropped.Add(1)
		return
	}
	cd, err := stun.DecodeChannelData(pkt)
	if err != nil {
		s.st.dropped.Add(1)
		return
	}
	a.fromClientChannel(cd)
}

func (s *Server) janitor() {
	defer s.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			now := s.cfg.Now()
			var dead []*allocation
			s.mu.RLock()
			for _, a := range s.allocs {
				if a.expired(now) {
					dead = append(dead, a)
				} else {
					a.prune(now)
				}
			}
			s.mu.RUnlock()
			for _, a := range dead {
				s.removeAlloc(a)
			}
		}
	}
}

func (s *Server) removeAlloc(a *allocation) {
	s.mu.Lock()
	if s.allocs[a.key] == a {
		delete(s.allocs, a.key)
		if s.perUser[a.user]--; s.perUser[a.user] <= 0 {
			delete(s.perUser, a.user)
		}
	}
	s.mu.Unlock()
	a.close()
}
