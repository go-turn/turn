package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-turn/turn/stun"
)

const testRealm = "turn.test"

var testUsers = map[string]string{"alice": "pw-alice", "bob": "pw-bob"}

func testAuth(u string) (string, bool) { p, ok := testUsers[u]; return p, ok }

// clock is a settable clock.
type clock struct{ off atomic.Int64 }

func (c *clock) Now() time.Time          { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *clock) Advance(d time.Duration) { c.off.Add(int64(d)) }

type env struct {
	srv   *Server
	clk   *clock
	udp   netip.AddrPort
	tcp   netip.AddrPort
	tcpLn net.Listener
	tls   netip.AddrPort
	cert  *x509.CertPool
}

// start launches a server relaying on 127.0.0.1 with every default; mut edits
// the Config first. withTCP also opens a TCP and a TLS listener.
func start(t testing.TB, withTCP bool, mut func(*Config)) *env {
	t.Helper()
	e := &env{clk: &clock{}}
	cfg := Config{Realm: testRealm, Auth: testAuth, RelayIP: netip.MustParseAddr("127.0.0.1"), Now: e.clk.Now}
	if mut != nil {
		mut(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	t.Cleanup(func() { srv.Close() })
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.udp = pc.LocalAddr().(*net.UDPAddr).AddrPort()
	go srv.ServePacketConn(pc)
	if withTCP {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		e.tcpLn = ln
		e.tcp = ln.Addr().(*net.TCPAddr).AddrPort()
		go srv.ServeListener(ln)
		ln2, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		e.tls = ln2.Addr().(*net.TCPAddr).AddrPort()
		cert, pool := selfSigned(t)
		e.cert = pool
		go srv.ServeTLS(ln2, &tls.Config{Certificates: []tls.Certificate{cert}})
	}
	return e
}

func loopbackAllow(c *Config) { c.AllowPeers = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} }

func selfSigned(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "turn.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"turn.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pool
}

// echoPeer is a UDP echo server on loopback.
func echoPeer(t testing.TB) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// client is a minimal raw TURN client for tests.
type client struct {
	t      testing.TB
	conn   net.Conn
	stream bool
	buf    []byte
	user   string
	pass   string
	realm  string
	nonce  string
	sha    bool
	queue  [][]byte
}

func dialUDP(t testing.TB, to netip.AddrPort) *client {
	t.Helper()
	c, err := net.Dial("udp", to.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &client{t: t, conn: c, user: "alice", pass: testUsers["alice"]}
}

func dialTCP(t testing.TB, to netip.AddrPort) *client {
	t.Helper()
	c, err := net.Dial("tcp", to.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &client{t: t, conn: c, stream: true, user: "alice", pass: testUsers["alice"]}
}

func dialTLS(t testing.TB, to netip.AddrPort, pool *x509.CertPool) *client {
	t.Helper()
	c, err := tls.Dial("tcp", to.String(), &tls.Config{RootCAs: pool, ServerName: "turn.test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &client{t: t, conn: c, stream: true, user: "alice", pass: testUsers["alice"]}
}

func (c *client) send(b []byte) {
	c.t.Helper()
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatal(err)
	}
}

// recv returns the next frame (a copy) or nil on timeout.
func (c *client) recv(d time.Duration) []byte {
	c.t.Helper()
	if len(c.queue) > 0 {
		f := c.queue[0]
		c.queue = c.queue[1:]
		return f
	}
	c.conn.SetReadDeadline(time.Now().Add(d))
	if c.stream {
		f, nb, err := stun.ReadFrame(c.conn, c.buf)
		c.buf = nb
		if err != nil {
			return nil
		}
		return append([]byte(nil), f...)
	}
	b := make([]byte, 65535)
	n, err := c.conn.Read(b)
	if err != nil {
		return nil
	}
	return b[:n]
}

// do sends m and returns the response with the same transaction ID; other
// frames are queued.
func (c *client) do(m *stun.Message) *stun.Message {
	c.t.Helper()
	b, err := m.Encode()
	if err != nil {
		c.t.Fatal(err)
	}
	c.send(b)
	var skipped [][]byte
	defer func() { c.queue = append(skipped, c.queue...) }()
	// UDP may lose a datagram (a CI runner under load did); the server
	// answers a retransmission of the same transaction idempotently.
	wait := 700 * time.Millisecond
	if c.stream {
		wait = 3 * time.Second
	}
	for tries := 0; ; {
		f := c.recv(wait)
		if f == nil {
			if tries++; tries >= 5 || c.stream {
				c.t.Fatalf("no response to %v", m.Method)
			}
			c.send(b)
			continue
		}
		if stun.IsMessage(f) {
			r, err := stun.Decode(f)
			if err == nil && r.TxID == m.TxID && (r.Class == stun.ClassSuccess || r.Class == stun.ClassError) {
				return r
			}
		}
		skipped = append(skipped, f)
	}
}

// req builds a request authenticated with the current credentials.
func (c *client) req(method stun.Method, fill func(*stun.Message)) *stun.Message {
	m := stun.New(stun.ClassRequest, method)
	if fill != nil {
		fill(m)
	}
	if c.nonce != "" {
		m.AddString(stun.AttrUsername, c.user)
		m.AddString(stun.AttrRealm, c.realm)
		m.AddString(stun.AttrNonce, c.nonce)
		if c.sha {
			m.AddPasswordAlgorithm(stun.PasswordAlgorithm{Algorithm: stun.AlgSHA256})
			m.SetIntegritySHA256(stun.LongTermKeySHA256(c.user, c.realm, c.pass), 0)
		} else {
			m.SetIntegrity(stun.LongTermKeyMD5(c.user, c.realm, c.pass))
		}
	}
	return m
}

// authed runs a request, answering a 401/438 challenge once.
func (c *client) authed(method stun.Method, fill func(*stun.Message)) *stun.Message {
	c.t.Helper()
	r := c.do(c.req(method, fill))
	if code, _, err := r.ErrorCode(); err == nil && (code == 401 || code == 438) {
		if n, ok := r.String(stun.AttrNonce); ok {
			c.nonce = n
			c.realm, _ = r.String(stun.AttrRealm)
			r = c.do(c.req(method, fill))
		}
	}
	return r
}

func errCode(t testing.TB, r *stun.Message) int {
	t.Helper()
	if r.Class != stun.ClassError {
		t.Fatalf("expected an error response, got class %v", r.Class)
	}
	code, _, err := r.ErrorCode()
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func mustSuccess(t testing.TB, r *stun.Message) {
	t.Helper()
	if r.Class != stun.ClassSuccess {
		code, reason, _ := r.ErrorCode()
		t.Fatalf("expected success, got %d %s", code, reason)
	}
}

func (c *client) allocate(fill func(*stun.Message)) *stun.Message {
	c.t.Helper()
	return c.authed(stun.MethodAllocate, func(m *stun.Message) {
		m.AddRequestedTransport(17)
		if fill != nil {
			fill(m)
		}
	})
}

func relayedOf(t testing.TB, r *stun.Message) netip.AddrPort {
	t.Helper()
	mustSuccess(t, r)
	a, err := r.Addr(stun.AttrXORRelayedAddress)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (c *client) permit(peers ...netip.AddrPort) *stun.Message {
	return c.authed(stun.MethodCreatePermission, func(m *stun.Message) {
		for _, p := range peers {
			m.AddAddr(stun.AttrXORPeerAddress, p)
		}
	})
}

func (c *client) bind(n uint16, peer netip.AddrPort) *stun.Message {
	return c.authed(stun.MethodChannelBind, func(m *stun.Message) {
		m.AddChannelNumber(n)
		m.AddAddr(stun.AttrXORPeerAddress, peer)
	})
}

func (c *client) sendInd(peer netip.AddrPort, data []byte) {
	m := stun.New(stun.ClassIndication, stun.MethodSend)
	m.AddAddr(stun.AttrXORPeerAddress, peer)
	m.Add(stun.AttrData, data)
	b, _ := m.Encode()
	c.send(b)
}

func (c *client) sendChan(n uint16, data []byte) {
	c.send(stun.ChannelData{Number: n, Data: data}.AppendTo(nil, c.stream))
}

// data waits for relayed data: a Data indication (peer, payload) or a
// ChannelData frame (channel number in ch). ok is false on timeout.
func (c *client) data(d time.Duration) (peer netip.AddrPort, ch uint16, payload []byte, ok bool) {
	c.t.Helper()
	for {
		f := c.recv(d)
		if f == nil {
			return
		}
		if stun.IsChannelData(f) {
			cd, err := stun.DecodeChannelData(f)
			if err != nil {
				c.t.Fatal(err)
			}
			return netip.AddrPort{}, cd.Number, cd.Data, true
		}
		m, err := stun.Decode(f)
		if err == nil && m.Class == stun.ClassIndication && m.Method == stun.MethodData {
			p, _ := m.Addr(stun.AttrXORPeerAddress)
			v, _ := m.Get(stun.AttrData)
			return p, 0, v, true
		}
	}
}
