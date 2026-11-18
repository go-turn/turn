package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/go-turn/turn/stun"
)

const maxUsername = 513 // RFC 8489 section 14.3

// known lists the comprehension-required attributes this server understands;
// any other type below 0x8000 in a request is answered 420 (RFC 8489 7.3.1).
// DONT-FRAGMENT, EVEN-PORT, RESERVATION-TOKEN and ADDITIONAL-ADDRESS-FAMILY
// are deliberately absent: they are unsupported, which RFC 8656 treats as
// unknown.
func known(t stun.AttrType) bool {
	switch t {
	case stun.AttrUsername, stun.AttrMessageIntegrity, stun.AttrMessageIntegritySHA256,
		stun.AttrRealm, stun.AttrNonce, stun.AttrPasswordAlgorithm, stun.AttrLifetime,
		stun.AttrXORPeerAddress, stun.AttrChannelNumber, stun.AttrRequestedTransport,
		stun.AttrRequestedAddressFamily, stun.AttrData, stun.AttrErrorCode, stun.AttrUnknownAttributes,
		stun.AttrMappedAddress, stun.AttrXORMappedAddress:
		return true
	}
	return false
}

func (s *Server) newNonce(ip netip.Addr, now time.Time) string {
	var b [24]byte
	binary.BigEndian.PutUint64(b[:8], uint64(now.UnixNano()))
	mac := hmac.New(sha256.New, s.secret[:])
	mac.Write(b[:8])
	mac.Write(ip.AsSlice())
	copy(b[8:], mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (s *Server) checkNonce(n string, ip netip.Addr, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil || len(raw) != 24 {
		return false
	}
	mac := hmac.New(sha256.New, s.secret[:])
	mac.Write(raw[:8])
	mac.Write(ip.AsSlice())
	if !hmac.Equal(mac.Sum(nil)[:16], raw[8:]) {
		return false
	}
	age := now.Sub(time.Unix(0, int64(binary.BigEndian.Uint64(raw[:8]))))
	return age < s.cfg.NonceLifetime && age > -5*time.Second
}

func (s *Server) reply(tr transport, to netip.AddrPort, m *stun.Message) {
	b, err := m.Encode()
	if err != nil {
		s.cfg.Logger.Warn("encode reply", "err", err)
		return
	}
	tr.send(to, b)
}

// fail answers req with an error response; auth adds REALM and a fresh NONCE.
func (s *Server) fail(tr transport, to netip.AddrPort, req *stun.Message, code int, reason string, auth bool) {
	r := &stun.Message{Class: stun.ClassError, Method: req.Method, TxID: req.TxID}
	r.AddError(code, reason)
	if auth {
		r.AddString(stun.AttrRealm, s.cfg.Realm)
		r.AddString(stun.AttrNonce, s.newNonce(to.Addr(), s.cfg.Now()))
		if code == stun.CodeUnauthenticated {
			r.AddPasswordAlgorithms([]stun.PasswordAlgorithm{{Algorithm: stun.AlgSHA256}, {Algorithm: stun.AlgMD5}})
		}
	}
	r.AddString(stun.AttrSoftware, s.cfg.Software)
	s.reply(tr, to, r)
}

type creds struct {
	user string
	key  []byte
	sha  bool
}

// ok answers req with a success response protected by c.
func (s *Server) ok(tr transport, to netip.AddrPort, req *stun.Message, c creds, fill func(*stun.Message)) []byte {
	r := &stun.Message{Class: stun.ClassSuccess, Method: req.Method, TxID: req.TxID}
	fill(r)
	r.AddString(stun.AttrSoftware, s.cfg.Software)
	if c.sha {
		r.SetIntegritySHA256(c.key, 0)
	} else {
		r.SetIntegrity(c.key)
	}
	b, err := r.Encode()
	if err != nil {
		s.cfg.Logger.Warn("encode reply", "err", err)
		return nil
	}
	tr.send(to, b)
	return b
}

// authenticate implements the long-term credential checks of RFC 8489 9.2.4
// (and RFC 8656 section 5). On failure it has already replied.
func (s *Server) authenticate(tr transport, from netip.AddrPort, m *stun.Message) (creds, bool) {
	_, hasMI := m.Get(stun.AttrMessageIntegrity)
	_, hasSHA := m.Get(stun.AttrMessageIntegritySHA256)
	if !hasMI && !hasSHA {
		s.fail(tr, from, m, stun.CodeUnauthenticated, "Unauthenticated", true)
		return creds{}, false
	}
	user, uok := m.String(stun.AttrUsername)
	realm, rok := m.String(stun.AttrRealm)
	nonce, nok := m.String(stun.AttrNonce)
	if !uok || !rok || !nok || len(user) > maxUsername || len(user) == 0 {
		s.fail(tr, from, m, stun.CodeBadRequest, "Bad Request", false)
		return creds{}, false
	}
	sha := false
	if _, present := m.Get(stun.AttrPasswordAlgorithm); present {
		alg, err := m.PasswordAlgorithm()
		switch {
		case err != nil || (alg.Algorithm != stun.AlgSHA256 && alg.Algorithm != stun.AlgMD5):
			s.fail(tr, from, m, stun.CodeBadRequest, "Bad Request", false)
			return creds{}, false
		case alg.Algorithm == stun.AlgSHA256:
			sha = true
		}
	}
	if sha && !hasSHA || !sha && !hasMI {
		s.fail(tr, from, m, stun.CodeBadRequest, "Bad Request", false)
		return creds{}, false
	}
	if !s.checkNonce(nonce, from.Addr(), s.cfg.Now()) {
		s.fail(tr, from, m, stun.CodeStaleNonce, "Stale Nonce", true)
		return creds{}, false
	}
	pw, ok := s.cfg.Auth(user)
	if !ok && s.cfg.AuthExisting != nil && m.Method != stun.MethodAllocate {
		// An expired username may keep ITS OWN allocation alive (RFC 8656 section
		// 5: the same credentials); the MESSAGE-INTEGRITY check below still
		// proves the client holds the password derived from it.
		if a := s.lookup(fiveTuple{from, tr.local(), tr.proto()}); a != nil && a.user == user &&
			s.cfg.Now().Sub(a.created) < s.cfg.MaxAllocationAge {
			pw, ok = s.cfg.AuthExisting(user)
		}
	}
	if !ok || realm != s.cfg.Realm {
		s.fail(tr, from, m, stun.CodeUnauthenticated, "Unauthenticated", true)
		return creds{}, false
	}
	var key []byte
	var err error
	if sha {
		key = stun.LongTermKeySHA256(user, realm, pw)
		err = m.CheckIntegritySHA256(key)
	} else {
		key = stun.LongTermKeyMD5(user, realm, pw)
		err = m.CheckIntegrity(key)
	}
	if err != nil {
		s.fail(tr, from, m, stun.CodeUnauthenticated, "Unauthenticated", true)
		return creds{}, false
	}
	return creds{user: user, key: key, sha: sha}, true
}

func (s *Server) handleSTUN(tr transport, from netip.AddrPort, m *stun.Message) {
	switch {
	case m.Class == stun.ClassRequest && m.Method == stun.MethodBinding:
		r := &stun.Message{Class: stun.ClassSuccess, Method: stun.MethodBinding, TxID: m.TxID}
		r.AddAddr(stun.AttrXORMappedAddress, from)
		r.AddString(stun.AttrSoftware, s.cfg.Software)
		r.SetFingerprint()
		s.reply(tr, from, r)
	case m.Class == stun.ClassIndication && m.Method == stun.MethodSend:
		s.handleSend(tr, from, m)
	case m.Class == stun.ClassRequest:
		switch m.Method {
		case stun.MethodAllocate, stun.MethodRefresh, stun.MethodCreatePermission, stun.MethodChannelBind:
		default:
			s.fail(tr, from, m, stun.CodeBadRequest, "Bad Request", false)
			return
		}
		c, ok := s.authenticate(tr, from, m)
		if !ok {
			return
		}
		var unk []stun.AttrType
		m.Each(func(a stun.Attribute) {
			if a.Type.ComprehensionRequired() && !known(a.Type) && len(unk) < 8 {
				unk = append(unk, a.Type)
			}
		})
		if len(unk) > 0 {
			r := &stun.Message{Class: stun.ClassError, Method: m.Method, TxID: m.TxID}
			r.AddError(stun.CodeUnknownAttribute, "Unknown Attribute")
			r.AddUnknownAttributes(unk)
			r.AddString(stun.AttrSoftware, s.cfg.Software)
			s.reply(tr, from, r)
			return
		}
		key := fiveTuple{from, tr.local(), tr.proto()}
		switch m.Method {
		case stun.MethodAllocate:
			s.handleAllocate(tr, from, m, c, key)
		default:
			a := s.lookup(key)
			if a == nil {
				s.fail(tr, from, m, stun.CodeAllocationMismatch, "Allocation Mismatch", false)
				return
			}
			if a.user != c.user {
				s.fail(tr, from, m, stun.CodeWrongCredentials, "Wrong Credentials", false)
				return
			}
			switch m.Method {
			case stun.MethodRefresh:
				s.handleRefresh(tr, from, m, c, a)
			case stun.MethodCreatePermission:
				s.handleCreatePermission(tr, from, m, c, a)
			case stun.MethodChannelBind:
				s.handleChannelBind(tr, from, m, c, a)
			}
		}
	default:
		s.st.dropped.Add(1)
	}
}

func (s *Server) handleSend(tr transport, from netip.AddrPort, m *stun.Message) {
	a := s.lookup(fiveTuple{from, tr.local(), tr.proto()})
	if a == nil {
		s.st.dropped.Add(1)
		return
	}
	peer, err := m.Addr(stun.AttrXORPeerAddress)
	data, ok := m.Get(stun.AttrData)
	if err != nil || !ok {
		s.st.dropped.Add(1)
		return
	}
	a.fromClientSend(ap(peer), data)
}

func (s *Server) lifetimeOf(m *stun.Message) (time.Duration, bool) {
	v, err := m.Uint32(stun.AttrLifetime)
	if err != nil {
		return s.cfg.DefaultLifetime, false
	}
	d := time.Duration(v) * time.Second
	if d > s.cfg.MaxLifetime {
		d = s.cfg.MaxLifetime
	}
	return d, true
}

func (s *Server) listenRelay() (*net.UDPConn, error) {
	network := "udp6"
	if s.cfg.RelayIP.Is4() {
		network = "udp4"
	}
	lo, hi := int(s.cfg.RelayPortMin), int(s.cfg.RelayPortMax)
	if lo == 0 && hi == 0 {
		return net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(s.cfg.RelayIP, 0)))
	}
	span := hi - lo + 1
	start := rand.IntN(span)
	var err error
	for i := 0; i < min(span, 1024); i++ {
		var c *net.UDPConn
		p := lo + (start+i)%span
		c, err = net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(s.cfg.RelayIP, uint16(p))))
		if err == nil {
			return c, nil
		}
	}
	return nil, err
}

func (s *Server) handleAllocate(tr transport, from netip.AddrPort, m *stun.Message, c creds, key fiveTuple) {
	if a := s.lookup(key); a != nil {
		a.mu.Lock()
		same := a.txid == m.TxID && a.user == c.user
		resp := a.resp
		a.mu.Unlock()
		if same {
			tr.send(from, resp) // retransmission: same answer
			return
		}
		s.fail(tr, from, m, stun.CodeAllocationMismatch, "Allocation Mismatch", false)
		return
	}
	proto, err := m.RequestedTransport()
	if err != nil {
		s.fail(tr, from, m, stun.CodeBadRequest, "Bad Request", false)
		return
	}
	if proto != protoUDP {
		s.fail(tr, from, m, stun.CodeUnsupportedProtocol, "Unsupported Transport Protocol", false)
		return
	}
	if _, present := m.Get(stun.AttrRequestedAddressFamily); present {
		f, err := m.RequestedAddressFamily()
		if err != nil {
			s.fail(tr, from, m, stun.CodeBadRequest, "Bad Request", false)
			return
		}
		if (f == stun.FamilyIPv4) != s.cfg.RelayIP.Is4() {
			s.fail(tr, from, m, stun.CodeAddrFamilyNotSupp, "Address Family not Supported", false)
			return
		}
	}
	life, set := s.lifetimeOf(m)
	if !set || life == 0 {
		life = s.cfg.DefaultLifetime
	}

	// Quotas are reserved before the socket is opened.
	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()
		return
	case s.perUser[c.user] >= s.cfg.MaxAllocationsPerUser:
		s.mu.Unlock()
		s.fail(tr, from, m, stun.CodeAllocQuota, "Allocation Quota Reached", false)
		return
	case len(s.allocs) >= s.cfg.MaxAllocations:
		s.mu.Unlock()
		s.fail(tr, from, m, stun.CodeInsufficientCap, "Insufficient Capacity", false)
		return
	}
	s.perUser[c.user]++
	s.mu.Unlock()
	release := func() {
		s.mu.Lock()
		if s.perUser[c.user]--; s.perUser[c.user] <= 0 {
			delete(s.perUser, c.user)
		}
		s.mu.Unlock()
	}

	relay, err := s.listenRelay()
	if err != nil {
		release()
		s.cfg.Logger.Warn("relay socket", "err", err)
		s.fail(tr, from, m, stun.CodeInsufficientCap, "Insufficient Capacity", false)
		return
	}
	local := ap(relay.LocalAddr().(*net.UDPAddr).AddrPort())
	now := s.cfg.Now()
	a := &allocation{
		s: s, key: key, user: c.user, created: now, tr: tr, client: from,
		relay:     relay,
		relayAddr: netip.AddrPortFrom(s.cfg.RelayAdvertiseIP, local.Port()),
		expires:   now.Add(life),
		perms:     make(map[netip.Addr]time.Time),
		byNum:     make(map[uint16]*channel),
		byPeer:    make(map[netip.AddrPort]*channel),
		txid:      m.TxID,
	}
	if s.cfg.MaxBytesPerSecond > 0 {
		a.rate.rate = float64(s.cfg.MaxBytesPerSecond)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		relay.Close()
		release()
		return
	}
	s.allocs[key] = a // perUser was already counted
	s.byPort[local.Port()] = a
	s.wg.Add(1)
	s.mu.Unlock()
	s.st.allocated.Add(1)
	go a.readLoop()

	a.mu.Lock()
	a.resp = s.ok(tr, from, m, c, func(r *stun.Message) {
		r.AddAddr(stun.AttrXORRelayedAddress, a.relayAddr)
		r.AddUint32(stun.AttrLifetime, uint32(life/time.Second))
		r.AddAddr(stun.AttrXORMappedAddress, from)
	})
	a.mu.Unlock()
	s.cfg.Logger.Debug("allocated", "user", c.user, "client", from, "relay", a.relayAddr)
}

func (s *Server) handleRefresh(tr transport, from netip.AddrPort, m *stun.Message, c creds, a *allocation) {
	life, set := s.lifetimeOf(m)
	if s.cfg.Now().Sub(a.created) >= s.cfg.MaxAllocationAge && !(set && life == 0) {
		// Past the age bound the allocation runs out its current lifetime; a
		// client that wants more allocates again with a fresh username. Deleting
		// (lifetime 0) stays allowed.
		s.cfg.Logger.Debug("refresh refused: allocation too old", "user", c.user, "client", from)
		s.fail(tr, from, m, stun.CodeForbidden, "Allocation Too Old", false)
		return
	}
	if set && life == 0 {
		s.ok(tr, from, m, c, func(r *stun.Message) { r.AddUint32(stun.AttrLifetime, 0) })
		s.removeAlloc(a)
		return
	}
	a.mu.Lock()
	a.expires = s.cfg.Now().Add(life)
	a.mu.Unlock()
	s.ok(tr, from, m, c, func(r *stun.Message) { r.AddUint32(stun.AttrLifetime, uint32(life/time.Second)) })
}

// peerChecks validates one XOR-PEER-ADDRESS: policy 403, family 443.
//
// An address of this server is a peer only at the relayed port of a live
// allocation (two clients relaying to each other): every other port of it, SSH,
// 443 or the TURN listener itself, stays 403. An address the operator allowlisted
// is the operator's decision, as before.
func (s *Server) peerCheck(p netip.AddrPort) int {
	if p.Port() == 0 {
		return stun.CodeForbidden
	}
	if s.pol.ownRestricted(p.Addr()) {
		if s.liveRelayPort(p.Port()) == nil {
			return stun.CodeForbidden
		}
	} else if !s.pol.permitted(p.Addr()) {
		return stun.CodeForbidden
	}
	if norm(p.Addr()).Is4() != s.cfg.RelayIP.Is4() {
		return stun.CodePeerAddrFamily
	}
	return 0
}

func (s *Server) handleCreatePermission(tr transport, from netip.AddrPort, m *stun.Message, c creds, a *allocation) {
	peers, err := m.Addrs(stun.AttrXORPeerAddress)
	if err != nil || len(peers) == 0 || len(peers) > 32 {
		s.fail(tr, from, m, stun.CodeBadRequest, "Bad Request", false)
		return
	}
	for _, p := range peers {
		if code := s.peerCheck(p); code != 0 {
			s.refuse(tr, from, m, code, p)
			return
		}
	}
	now := s.cfg.Now()
	a.mu.Lock()
	fresh := 0
	for _, p := range peers {
		if !a.permittedLocked(norm(p.Addr()), now) {
			fresh++
		}
	}
	if len(a.perms)+fresh > s.cfg.MaxPermissions {
		a.mu.Unlock()
		s.fail(tr, from, m, stun.CodeInsufficientCap, "Insufficient Capacity", false)
		return
	}
	for _, p := range peers {
		a.perms[norm(p.Addr())] = now.Add(permissionLifetime)
	}
	a.mu.Unlock()
	s.ok(tr, from, m, c, func(*stun.Message) {})
}

func (s *Server) refuse(tr transport, from netip.AddrPort, m *stun.Message, code int, p netip.AddrPort) {
	reason := "Forbidden"
	if code == stun.CodePeerAddrFamily {
		reason = "Peer Address Family Mismatch"
	}
	s.cfg.Logger.Debug("peer refused", "code", code, "peer", p, "client", from)
	s.fail(tr, from, m, code, reason, false)
}

func (s *Server) handleChannelBind(tr transport, from netip.AddrPort, m *stun.Message, c creds, a *allocation) {
	num, err := m.ChannelNumber()
	peer, perr := m.Addr(stun.AttrXORPeerAddress)
	if err != nil || perr != nil || num < stun.ChannelMin || num > stun.ChannelMax {
		s.fail(tr, from, m, stun.CodeBadRequest, "Bad Request", false)
		return
	}
	peer = ap(peer)
	if code := s.peerCheck(peer); code != 0 {
		s.refuse(tr, from, m, code, peer)
		return
	}
	now := s.cfg.Now()
	a.mu.Lock()
	cur := a.byNum[num]
	if cur != nil && !now.Before(cur.expires) {
		delete(a.byNum, num)
		if a.byPeer[cur.peer] == cur {
			delete(a.byPeer, cur.peer)
		}
		cur = nil
	}
	other := a.byPeer[peer]
	if other != nil && !now.Before(other.expires) {
		delete(a.byNum, other.number)
		delete(a.byPeer, peer)
		other = nil
	}
	switch {
	case (cur != nil && cur.peer != peer) || (other != nil && other.number != num):
		a.mu.Unlock()
		s.fail(tr, from, m, stun.CodeBadRequest, "Bad Request", false)
		return
	case cur == nil && len(a.byNum) >= s.cfg.MaxChannels:
		a.mu.Unlock()
		s.fail(tr, from, m, stun.CodeInsufficientCap, "Insufficient Capacity", false)
		return
	case !a.permittedLocked(peer.Addr(), now) && len(a.perms) >= s.cfg.MaxPermissions:
		a.mu.Unlock()
		s.fail(tr, from, m, stun.CodeInsufficientCap, "Insufficient Capacity", false)
		return
	}
	if cur == nil {
		cur = &channel{number: num, peer: peer}
		a.byNum[num] = cur
		a.byPeer[peer] = cur
	}
	cur.expires = now.Add(channelLifetime)
	a.perms[peer.Addr()] = now.Add(permissionLifetime)
	a.mu.Unlock()
	s.st.binds.Add(1)
	s.ok(tr, from, m, c, func(*stun.Message) {})
}
