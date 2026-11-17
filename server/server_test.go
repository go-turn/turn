package server

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/go-turn/turn/stun"
)

func TestBinding(t *testing.T) {
	e := start(t, true, nil)
	for name, c := range map[string]*client{
		"udp": dialUDP(t, e.udp), "tcp": dialTCP(t, e.tcp), "tls": dialTLS(t, e.tls, e.cert),
	} {
		m := stun.New(stun.ClassRequest, stun.MethodBinding)
		r := c.do(m)
		mustSuccess(t, r)
		got, err := r.Addr(stun.AttrXORMappedAddress)
		if err != nil {
			t.Fatal(name, err)
		}
		want := netip.MustParseAddrPort(c.conn.LocalAddr().String())
		if got != want {
			t.Fatalf("%s: mapped %v want %v", name, got, want)
		}
		if err := r.CheckFingerprint(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestAuthentication(t *testing.T) {
	e := start(t, false, nil)
	c := dialUDP(t, e.udp)

	// No credentials: 401 with REALM, NONCE and the algorithms.
	r := c.do(c.req(stun.MethodAllocate, func(m *stun.Message) { m.AddRequestedTransport(17) }))
	if errCode(t, r) != 401 {
		t.Fatal("want 401")
	}
	realm, _ := r.String(stun.AttrRealm)
	nonce, ok := r.String(stun.AttrNonce)
	if realm != testRealm || !ok {
		t.Fatal("401 lacks realm or nonce")
	}
	if algs, err := r.PasswordAlgorithms(); err != nil || len(algs) != 2 {
		t.Fatal("401 lacks PASSWORD-ALGORITHMS", err)
	}
	c.realm, c.nonce = realm, nonce

	// Wrong password and unknown user are indistinguishable.
	c.pass = "wrong"
	bad := c.do(c.req(stun.MethodAllocate, func(m *stun.Message) { m.AddRequestedTransport(17) }))
	c.user = "mallory"
	unknown := c.do(c.req(stun.MethodAllocate, func(m *stun.Message) { m.AddRequestedTransport(17) }))
	if errCode(t, bad) != 401 || errCode(t, unknown) != 401 {
		t.Fatal("want 401 for both")
	}
	r1, _ := bad.String(stun.AttrErrorCode)
	r2, _ := unknown.String(stun.AttrErrorCode)
	if r1 != r2 {
		t.Fatal("responses differ")
	}

	// Missing USERNAME with integrity present: 400.
	c.user, c.pass = "alice", testUsers["alice"]
	m := stun.New(stun.ClassRequest, stun.MethodAllocate)
	m.AddRequestedTransport(17)
	m.AddString(stun.AttrRealm, realm)
	m.AddString(stun.AttrNonce, nonce)
	m.SetIntegrity([]byte("x"))
	if errCode(t, c.do(m)) != 400 {
		t.Fatal("want 400")
	}

	// A forged nonce is stale (438), as is an expired one.
	c.nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	r = c.do(c.req(stun.MethodAllocate, func(m *stun.Message) { m.AddRequestedTransport(17) }))
	if errCode(t, r) != 438 {
		t.Fatal("forged nonce not refused with 438")
	}
	c.nonce = nonce
	mustSuccess(t, c.do(c.req(stun.MethodAllocate, func(m *stun.Message) { m.AddRequestedTransport(17) })))
	mustSuccess(t, c.do(c.req(stun.MethodRefresh, func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 3000) })))
	e.clk.Advance(11 * time.Minute) // NonceLifetime is 10 minutes
	r = c.do(c.req(stun.MethodRefresh, nil))
	if errCode(t, r) != 438 {
		t.Fatal("expired nonce not refused with 438")
	}
	fresh, ok := r.String(stun.AttrNonce)
	if !ok || fresh == nonce {
		t.Fatal("438 carries no fresh nonce")
	}
	c.nonce = fresh
	mustSuccess(t, c.do(c.req(stun.MethodRefresh, nil)))
}

func TestAuthSHA256(t *testing.T) {
	e := start(t, false, nil)
	c := dialUDP(t, e.udp)
	c.sha = true
	relayedOf(t, c.allocate(nil))
	// A SHA-256 request whose integrity was made with the MD5 key is refused.
	c.pass = "nope"
	if errCode(t, c.do(c.req(stun.MethodRefresh, nil))) != 401 {
		t.Fatal("want 401")
	}
}

func TestAllocateErrors(t *testing.T) {
	e := start(t, false, nil)
	c := dialUDP(t, e.udp)
	// Wrong transport: 442; missing: 400.
	if errCode(t, c.authed(stun.MethodAllocate, func(m *stun.Message) { m.AddRequestedTransport(6) })) != 442 {
		t.Fatal("want 442")
	}
	if errCode(t, c.authed(stun.MethodAllocate, nil)) != 400 {
		t.Fatal("want 400")
	}
	// Family IPv6 on an IPv4 relay: 440.
	if errCode(t, c.allocate(func(m *stun.Message) { m.AddRequestedAddressFamily(stun.FamilyIPv6) })) != 440 {
		t.Fatal("want 440")
	}
	// Unsupported comprehension-required attributes: 420 naming them.
	r := c.allocate(func(m *stun.Message) { m.Add(stun.AttrDontFragment, nil) })
	if errCode(t, r) != 420 {
		t.Fatal("want 420")
	}
	if u, err := r.UnknownAttributes(); err != nil || len(u) != 1 || u[0] != stun.AttrDontFragment {
		t.Fatal(u, err)
	}
	r = c.allocate(func(m *stun.Message) { m.AddEvenPort(stun.EvenPort{}) })
	if errCode(t, r) != 420 {
		t.Fatal("EVEN-PORT should be 420")
	}

	// Success, then a retransmission (same TxID) gets the same answer and a
	// new transaction on the same 5-tuple gets 437.
	first := c.req(stun.MethodAllocate, func(m *stun.Message) { m.AddRequestedTransport(17) })
	r1 := c.do(first)
	r2 := c.do(first)
	if relayedOf(t, r1) != relayedOf(t, r2) {
		t.Fatal("retransmission produced another allocation")
	}
	if errCode(t, c.allocate(nil)) != 437 {
		t.Fatal("want 437")
	}
	if got := e.srv.Stats().Allocations; got != 1 {
		t.Fatalf("%d allocations", got)
	}

	// Another user on the same 5-tuple: 441.
	c.user, c.pass = "bob", testUsers["bob"]
	if errCode(t, c.authed(stun.MethodRefresh, nil)) != 441 {
		t.Fatal("want 441")
	}
	c.user, c.pass = "alice", testUsers["alice"]

	// Refresh with LIFETIME 0 deletes; a later refresh finds nothing: 437.
	r = c.authed(stun.MethodRefresh, func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 0) })
	mustSuccess(t, r)
	if v, _ := r.Uint32(stun.AttrLifetime); v != 0 {
		t.Fatal("lifetime", v)
	}
	if errCode(t, c.authed(stun.MethodRefresh, nil)) != 437 {
		t.Fatal("want 437 after delete")
	}
	if got := e.srv.Stats().Allocations; got != 0 {
		t.Fatalf("%d allocations after delete", got)
	}
	// Permission without an allocation: 437.
	if errCode(t, c.permit(netip.MustParseAddrPort("203.0.113.9:1"))) != 437 {
		t.Fatal("want 437")
	}
}

func TestRelayUDPRoundTrip(t *testing.T) {
	e := start(t, false, loopbackAllow)
	peer := echoPeer(t)
	c := dialUDP(t, e.udp)
	relayed := relayedOf(t, c.allocate(nil))
	if relayed.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatal(relayed)
	}

	// Without a permission the data is dropped.
	c.sendInd(peer, []byte("early"))
	if _, _, _, ok := c.data(200 * time.Millisecond); ok {
		t.Fatal("data relayed without permission")
	}

	mustSuccess(t, c.permit(peer))
	c.sendInd(peer, []byte("ping"))
	// The echo comes from the peer to the relayed address.
	p, _, d, ok := c.data(2 * time.Second)
	if !ok || string(d) != "ping" || p != peer {
		t.Fatalf("data %v %q %v", p, d, ok)
	}

	// Channel binding: ChannelData both ways.
	mustSuccess(t, c.bind(0x4001, peer))
	c.sendChan(0x4001, []byte("chan"))
	_, ch, d, ok := c.data(2 * time.Second)
	if !ok || ch != 0x4001 || string(d) != "chan" {
		t.Fatalf("channel %x %q %v", ch, d, ok)
	}
	// Rebinding the same pair is fine; a conflicting one is 400.
	mustSuccess(t, c.bind(0x4001, peer))
	other := netip.MustParseAddrPort("127.0.0.1:9")
	if errCode(t, c.bind(0x4001, other)) != 400 {
		t.Fatal("channel reuse for another peer accepted")
	}
	if errCode(t, c.bind(0x4002, peer)) != 400 {
		t.Fatal("second channel for a bound peer accepted")
	}
	// Channel numbers outside 0x4000-0x4FFF: 400.
	if errCode(t, c.bind(0x5000, other)) != 400 || errCode(t, c.bind(0x3fff, other)) != 400 {
		t.Fatal("bad channel number accepted")
	}
	// Data on an unbound channel is dropped, not relayed.
	c.sendChan(0x4009, []byte("x"))
	// An empty ChannelData (zero length) is valid.
	c.sendChan(0x4001, nil)
	if _, _, d, ok := c.data(300 * time.Millisecond); ok && len(d) != 0 {
		t.Fatalf("unexpected %q", d)
	}
}

func TestPermissionAndChannelExpiry(t *testing.T) {
	e := start(t, false, loopbackAllow)
	peer := echoPeer(t)
	c := dialUDP(t, e.udp)
	relayedOf(t, c.allocate(nil))
	mustSuccess(t, c.authed(stun.MethodRefresh, func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 3600) }))
	mustSuccess(t, c.permit(peer))
	mustSuccess(t, c.bind(0x4010, peer))

	e.clk.Advance(299 * time.Second)
	c.sendChan(0x4010, []byte("a"))
	if _, _, _, ok := c.data(2 * time.Second); !ok {
		t.Fatal("channel dead before 300 s")
	}
	// Past 300 s the permission is gone: Send is dropped. The channel
	// (600 s) is still bound but its permission has lapsed too, so the
	// echo is not delivered.
	e.clk.Advance(2 * time.Second)
	c.sendInd(peer, []byte("b"))
	if _, _, _, ok := c.data(300 * time.Millisecond); ok {
		t.Fatal("Send relayed after the 300 s permission lapsed")
	}
	// Re-permitting restores it; the channel binding survives until 600 s.
	mustSuccess(t, c.permit(peer))
	c.sendChan(0x4010, []byte("c"))
	if _, ch, _, ok := c.data(2 * time.Second); !ok || ch != 0x4010 {
		t.Fatal("bound channel lost before 600 s")
	}
	e.clk.Advance(601 * time.Second)
	mustSuccess(t, c.permit(peer))
	c.sendChan(0x4010, []byte("d"))
	if _, _, _, ok := c.data(300 * time.Millisecond); ok {
		t.Fatal("channel relayed after the 600 s lifetime")
	}
}

func TestAllocationExpires(t *testing.T) {
	e := start(t, false, nil)
	c := dialUDP(t, e.udp)
	r := c.allocate(func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 30) })
	relayedOf(t, r)
	if v, _ := r.Uint32(stun.AttrLifetime); v != 30 {
		t.Fatal(v)
	}
	e.clk.Advance(31 * time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for e.srv.Stats().Allocations != 0 {
		if time.Now().After(deadline) {
			t.Fatal("expired allocation not reaped")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestMaxLifetimeClamp(t *testing.T) {
	e := start(t, false, func(c *Config) { c.MaxLifetime = 120 * time.Second; c.DefaultLifetime = time.Hour })
	c := dialUDP(t, e.udp)
	r := c.allocate(func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 99999) })
	relayedOf(t, r)
	if v, _ := r.Uint32(stun.AttrLifetime); v != 120 {
		t.Fatalf("lifetime %d not clamped to 120", v)
	}
	r = c.authed(stun.MethodRefresh, func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 4000000000) })
	mustSuccess(t, r)
	if v, _ := r.Uint32(stun.AttrLifetime); v != 120 {
		t.Fatalf("refresh lifetime %d not clamped", v)
	}
	// DefaultLifetime above the cap is lowered to it.
	r = dialUDPAs(t, e.udp, "bob").allocate(nil)
	if v, _ := r.Uint32(stun.AttrLifetime); v != 120 {
		t.Fatalf("default lifetime %d above the cap", v)
	}
}

func dialUDPAs(t testing.TB, to netip.AddrPort, user string) *client {
	c := dialUDP(t, to)
	c.user, c.pass = user, testUsers[user]
	return c
}

func TestQuotas(t *testing.T) {
	e := start(t, false, func(c *Config) { c.MaxAllocationsPerUser = 2; c.MaxAllocations = 3 })
	a1, a2, a3 := dialUDP(t, e.udp), dialUDP(t, e.udp), dialUDP(t, e.udp)
	relayedOf(t, a1.allocate(nil))
	relayedOf(t, a2.allocate(nil))
	// Third allocation for alice: per-user quota, 486.
	if errCode(t, a3.allocate(nil)) != 486 {
		t.Fatal("want 486")
	}
	// bob takes the third slot; the next one hits the total, 508.
	b1, b2 := dialUDPAs(t, e.udp, "bob"), dialUDPAs(t, e.udp, "bob")
	relayedOf(t, b1.allocate(nil))
	if errCode(t, b2.allocate(nil)) != 508 {
		t.Fatal("want 508")
	}
	// Deleting one frees a slot.
	mustSuccess(t, a1.authed(stun.MethodRefresh, func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 0) }))
	relayedOf(t, b2.allocate(nil))
	if got := e.srv.Stats().Allocations; got != 3 {
		t.Fatalf("%d allocations", got)
	}
}

func TestRelayPortRange(t *testing.T) {
	// Pick a free window of 3 ports.
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	base := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	lo, hi := uint16(base), uint16(base+2)
	e := start(t, false, func(c *Config) { c.RelayPortMin, c.RelayPortMax = lo, hi })
	var seen []uint16
	for i := 0; i < 3; i++ {
		c := dialUDPAs(t, e.udp, []string{"alice", "bob", "bob"}[i])
		p := relayedOf(t, c.allocate(nil)).Port()
		if p < lo || p > hi {
			t.Fatalf("port %d outside %d-%d", p, lo, hi)
		}
		seen = append(seen, p)
	}
	if seen[0] == seen[1] || seen[1] == seen[2] || seen[0] == seen[2] {
		t.Fatalf("ports reused: %v", seen)
	}
	// The window is exhausted: 508.
	c := dialUDPAs(t, e.udp, "bob")
	if errCode(t, c.allocate(nil)) != 508 {
		t.Fatal("want 508 with the port range exhausted")
	}
}

func TestByteRateCap(t *testing.T) {
	e := start(t, false, func(c *Config) { loopbackAllow(c); c.MaxBytesPerSecond = 2000 })
	peer := echoPeer(t)
	c := dialUDP(t, e.udp)
	relayedOf(t, c.allocate(nil))
	mustSuccess(t, c.permit(peer))
	mustSuccess(t, c.bind(0x4001, peer))
	payload := bytes.Repeat([]byte{1}, 100)
	for i := 0; i < 200; i++ { // 20000 bytes against a 2000 B/s bucket
		c.sendChan(0x4001, payload)
	}
	for {
		if _, _, _, ok := c.data(400 * time.Millisecond); !ok {
			break
		}
	}
	// One bucket of 2000 B serves both directions: about 20 packets of
	// 100 B reach the peer, the other 180 are dropped.
	got := e.srv.Stats().PacketsToPeer
	if got == 0 || got > 30 {
		t.Fatalf("%d of 200 packets relayed under a 2000 B/s cap", got)
	}
	if e.srv.Stats().Dropped == 0 {
		t.Fatal("no drops counted")
	}
}

func TestOversizeFromPeerIsDropped(t *testing.T) {
	e := start(t, false, func(c *Config) { loopbackAllow(c); c.RelayBufSize = 600 })
	peer := echoPeer(t)
	c := dialUDP(t, e.udp)
	relayedOf(t, c.allocate(nil))
	mustSuccess(t, c.permit(peer))
	c.sendInd(peer, bytes.Repeat([]byte{1}, 1000))
	if _, _, _, ok := c.data(300 * time.Millisecond); ok {
		t.Fatal("datagram above RelayBufSize relayed")
	}
	c.sendInd(peer, []byte("small"))
	if _, _, d, ok := c.data(2 * time.Second); !ok || string(d) != "small" {
		t.Fatal("small datagram lost")
	}
}

func TestUnpermittedPeerCannotReachRelay(t *testing.T) {
	e := start(t, false, loopbackAllow)
	c := dialUDP(t, e.udp)
	relayed := relayedOf(t, c.allocate(nil))
	mustSuccess(t, c.permit(netip.MustParseAddrPort("127.0.0.2:1")))
	// A datagram from 127.0.0.1 (not permitted) to the relayed address.
	pc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relayed))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	before := e.srv.Stats().Dropped
	pc.Write([]byte("hi"))
	if _, _, _, ok := c.data(300 * time.Millisecond); ok {
		t.Fatal("data from an unpermitted source relayed")
	}
	if e.srv.Stats().Dropped == before {
		t.Fatal("drop not counted")
	}
}

func TestTCPAndTLSRelay(t *testing.T) {
	e := start(t, true, loopbackAllow)
	peer := echoPeer(t)
	for name, c := range map[string]*client{"tcp": dialTCP(t, e.tcp), "tls": dialTLS(t, e.tls, e.cert)} {
		relayedOf(t, c.allocate(nil))
		mustSuccess(t, c.permit(peer))
		c.sendInd(peer, []byte("over "+name))
		if _, _, d, ok := c.data(2 * time.Second); !ok || string(d) != "over "+name {
			t.Fatalf("%s: data %q %v", name, d, ok)
		}
		mustSuccess(t, c.bind(0x4003, peer))
		// Stream ChannelData is padded to 4 bytes; 5 bytes of payload.
		c.sendChan(0x4003, []byte("hello"))
		_, ch, d, ok := c.data(2 * time.Second)
		if !ok || ch != 0x4003 || string(d) != "hello" {
			t.Fatalf("%s: channel %x %q %v", name, ch, d, ok)
		}
		c.conn.Close()
	}
	// Closing the connection deletes its allocation.
	deadline := time.Now().Add(3 * time.Second)
	for e.srv.Stats().Allocations != 0 {
		if time.Now().After(deadline) {
			t.Fatal("allocation outlived its TCP connection")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestStreamBounds(t *testing.T) {
	e := start(t, true, func(c *Config) { c.MaxConns = 2; c.HandshakeTimeout = 300 * time.Millisecond })
	closedWithin := func(c *client, d time.Duration) bool {
		c.conn.SetReadDeadline(time.Now().Add(d))
		_, err := c.conn.Read(make([]byte, 1))
		ne, isNet := err.(net.Error)
		return err != nil && !(isNet && ne.Timeout())
	}
	// Garbage framing closes the connection.
	g := dialTCP(t, e.tcp)
	g.send([]byte{0xff, 0, 0, 0})
	if !closedWithin(g, 2*time.Second) {
		t.Fatal("junk frame did not close the connection")
	}
	// A STUN header claiming 64 KiB that never arrives is cut at the
	// handshake timeout, not held open.
	s := dialTCP(t, e.tcp)
	s.send([]byte{0, 1, 0xff, 0xfc, 0x21, 0x12, 0xa4, 0x42})
	if !closedWithin(s, 3*time.Second) {
		t.Fatal("stalled frame held the connection open")
	}
	// Unaligned STUN length closes it.
	u := dialTCP(t, e.tcp)
	u.send([]byte{0, 1, 0, 3})
	if !closedWithin(u, 2*time.Second) {
		t.Fatal("unaligned length did not close the connection")
	}
	// Connection cap: with two idle connections the third is closed.
	c1, c2 := dialTCP(t, e.tcp), dialTCP(t, e.tcp)
	_ = c1
	_ = c2
	time.Sleep(50 * time.Millisecond)
	c3 := dialTCP(t, e.tcp)
	if !closedWithin(c3, 2*time.Second) {
		t.Fatal("connection above MaxConns accepted")
	}
}

func TestCloseStopsEverything(t *testing.T) {
	e := start(t, true, loopbackAllow)
	c := dialUDP(t, e.udp)
	relayedOf(t, c.allocate(nil))
	tc := dialTCP(t, e.tcp)
	relayedOf(t, tc.allocate(nil))
	done := make(chan struct{})
	go func() { e.srv.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hangs")
	}
	if e.srv.Stats().Allocations != 0 {
		t.Fatal("allocations survive Close")
	}
	if err := e.srv.ServePacketConn(nil); err != ErrClosed {
		t.Fatalf("serve after close: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	ok := Config{Realm: "r", Auth: testAuth, RelayIP: netip.MustParseAddr("127.0.0.1")}
	for name, mut := range map[string]func(*Config){
		"no realm":   func(c *Config) { c.Realm = "" },
		"no auth":    func(c *Config) { c.Auth = nil },
		"no relayip": func(c *Config) { c.RelayIP = netip.Addr{} },
		"bad range":  func(c *Config) { c.RelayPortMin, c.RelayPortMax = 20, 10 },
		"family":     func(c *Config) { c.RelayAdvertiseIP = netip.MustParseAddr("::1") },
		"buf":        func(c *Config) { c.RelayBufSize = 10 },
	} {
		c := ok
		mut(&c)
		if s, err := New(c); err == nil {
			s.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	s, err := New(ok)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}
