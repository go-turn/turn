package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/fs"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-turn/turn/creds"
	"github.com/go-turn/turn/server"
	"github.com/go-turn/turn/stun"
)

const testRealm = "turn.test"

// relay is an in-process server.Server on loopback with every transport.
type relay struct {
	udp, tcp, tls string // host:port
	pool          *x509.CertPool
	ring          *creds.Keyring
	sni           atomic.Value // the last SNI the TLS listener saw
}

func selfSigned(t *testing.T, dnsNames ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "turn.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: dnsNames, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if len(dnsNames) == 0 {
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
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

// startRelay serves UDP, TCP and TLS. allowLoopback re-enables loopback peers
// the way the server's own tests do; without it the server refuses to relay to
// its own address.
func startRelay(t *testing.T, allowLoopback bool, certNames ...string) *relay {
	t.Helper()
	ring, err := creds.NewKeyring([]byte("0123456789abcdef-secret"))
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{ring: ring}
	cfg := server.Config{Realm: testRealm, Auth: ring.Auth(nil), RelayIP: netip.MustParseAddr("127.0.0.1")}
	if allowLoopback {
		cfg.AllowPeers = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	}
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	r.udp = pc.LocalAddr().String()
	go srv.ServePacketConn(pc)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	r.tcp = ln.Addr().String()
	go srv.ServeListener(ln)
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln2.Close() })
	r.tls = ln2.Addr().String()
	cert, pool := selfSigned(t, certNames...)
	r.pool = pool
	go srv.ServeTLS(ln2, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			r.sni.Store(h.ServerName)
			return &cert, nil
		},
	})
	return r
}

func (r *relay) mint(t *testing.T, expiry time.Time) (user, pass string) {
	t.Helper()
	return r.ring.Mint("probe", expiry)
}

// cli runs turnprobe and returns its stdout and error.
func cli(t *testing.T, pool *x509.CertPool, username, password string, args ...string) (string, error) {
	t.Helper()
	old := probeCfg
	probeCfg = probeConfig{RootCAs: pool}
	t.Cleanup(func() { probeCfg = old })
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	cmd := RootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(append([]string{"--username", username, "--password-file", pwFile}, args...))
	err := cmd.Execute()
	if strings.Contains(out.String(), password) || strings.Contains(errb.String(), password) {
		t.Errorf("the password was printed: %q %q", out.String(), errb.String())
	}
	return out.String(), err
}

func TestProbePassesOverUDPTCPAndTLS(t *testing.T) {
	r := startRelay(t, true, "localhost")
	user, pass := r.mint(t, time.Now().Add(10*time.Minute))
	_, tlsPort, _ := net.SplitHostPort(r.tls)
	servers := []string{
		"turn:" + r.udp + "?transport=udp",
		"turn:" + r.tcp + "?transport=tcp",
		"turns:localhost:" + tlsPort + "?transport=tcp",
	}
	args := []string{"--realm", testRealm}
	for _, s := range servers {
		args = append(args, "--server", s)
	}
	out, err := cli(t, r.pool, user, pass, args...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != len(servers) {
		t.Fatalf("want one line per server, got:\n%s", out)
	}
	for i, l := range lines {
		for _, want := range []string{"PASS " + servers[i], "mapped=127.0.0.1:", "relay-a=127.0.0.1:", "relay-b=127.0.0.1:"} {
			if !strings.Contains(l, want) {
				t.Errorf("line %q lacks %q", l, want)
			}
		}
	}
	if sni, _ := r.sni.Load().(string); sni != "localhost" {
		t.Errorf("SNI %q, want the host %q", sni, "localhost")
	}
}

// The server does not allowlist its own address (no AllowPeers): two
// allocations on it relay to each other because the peer's port is the relayed
// port of a live allocation. This is the rule that makes the probe work on a
// deployed relay, over every transport.
func TestProbePassesWithoutAllowlistingOwnAddress(t *testing.T) {
	r := startRelay(t, false, "localhost")
	user, pass := r.mint(t, time.Now().Add(10*time.Minute))
	_, tlsPort, _ := net.SplitHostPort(r.tls)
	out, err := cli(t, r.pool, user, pass, "--realm", testRealm,
		"--server", "turn:"+r.udp+"?transport=udp",
		"--server", "turn:"+r.tcp+"?transport=tcp",
		"--server", "turns:localhost:"+tlsPort+"?transport=tcp")
	if err != nil || strings.Count(out, "PASS ") != 3 {
		t.Fatalf("%v\n%s", err, out)
	}
}

// fakeTURN is a UDP "relay" that answers like one until a stage where it
// misbehaves on purpose: it never relays (mode "drop"), or relays only what the
// first allocation sends (mode "oneway"), or does not answer at all ("mute").
type fakeTURN struct {
	pc    net.PacketConn
	mode  string
	mu    sync.Mutex
	next  uint16
	order []string                  // client addresses in allocation order
	relOf map[string]netip.AddrPort // client -> relayed address
	byPrt map[uint16]net.Addr       // relayed port -> client
}

func startFake(t *testing.T, mode string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	f := &fakeTURN{pc: pc, mode: mode, next: 40000, relOf: map[string]netip.AddrPort{}, byPrt: map[uint16]net.Addr{}}
	go f.loop()
	return pc.LocalAddr().String()
}

func (f *fakeTURN) loop() {
	buf := make([]byte, 65535)
	for {
		n, from, err := f.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if f.mode == "mute" {
			continue
		}
		m, err := stun.Decode(append([]byte(nil), buf[:n]...))
		if err != nil {
			continue
		}
		f.handle(m, from)
	}
}

func (f *fakeTURN) reply(from net.Addr, m *stun.Message) {
	b, _ := m.Encode()
	f.pc.WriteTo(b, from)
}

func (f *fakeTURN) handle(m *stun.Message, from net.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ok := func() *stun.Message {
		r := stun.New(stun.ClassSuccess, m.Method)
		r.TxID = m.TxID
		return r
	}
	switch {
	case m.Class == stun.ClassRequest && m.Method == stun.MethodBinding:
		r := ok()
		r.AddAddr(stun.AttrXORMappedAddress, from.(*net.UDPAddr).AddrPort())
		f.reply(from, r)
	case m.Class == stun.ClassRequest && m.Method == stun.MethodAllocate:
		if _, signed := m.Get(stun.AttrUsername); !signed {
			r := stun.New(stun.ClassError, m.Method)
			r.TxID = m.TxID
			r.AddError(401, "Unauthorized")
			r.AddString(stun.AttrRealm, testRealm)
			r.AddString(stun.AttrNonce, "fake-nonce")
			f.reply(from, r)
			return
		}
		rel, have := f.relOf[from.String()]
		if !have {
			f.next++
			rel = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), f.next)
			f.relOf[from.String()] = rel
			f.byPrt[rel.Port()] = from
			f.order = append(f.order, from.String())
		}
		r := ok()
		r.AddAddr(stun.AttrXORRelayedAddress, rel)
		f.reply(from, r)
	case m.Class == stun.ClassRequest && m.Method == stun.MethodCreatePermission && f.mode == "forbid":
		r := stun.New(stun.ClassError, m.Method)
		r.TxID = m.TxID
		r.AddError(403, "Forbidden")
		f.reply(from, r)
	case m.Class == stun.ClassRequest:
		f.reply(from, ok())
	case m.Class == stun.ClassIndication && m.Method == stun.MethodSend:
		if f.mode == "drop" || (f.mode == "oneway" && from.String() != f.order[0]) {
			return
		}
		peer, err := m.Addr(stun.AttrXORPeerAddress)
		data, _ := m.Get(stun.AttrData)
		if err != nil {
			return
		}
		if to, found := f.byPrt[peer.Port()]; found {
			b := stun.AppendDataIndication(nil, stun.NewTxID(), f.relOf[from.String()], data)
			f.pc.WriteTo(b, to)
		}
	}
}

func TestProbeFailuresNameTheirStage(t *testing.T) {
	good := startRelay(t, true)
	user, pass := good.mint(t, time.Now().Add(10*time.Minute))
	expiredUser, expiredPass := good.mint(t, time.Now().Add(-time.Minute))

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	closed.Close()
	_, tlsPort, _ := net.SplitHostPort(good.tls)

	cases := []struct {
		name     string
		server   string
		user     string
		pass     string
		realm    string
		roots    *x509.CertPool
		stage    string
		contains string
	}{
		{"connect: nothing listens", "turn:" + closedAddr + "?transport=tcp", user, pass, testRealm, nil, stageConnect, "refused"},
		{"connect: turns certificate not in the roots", "turns:" + good.tls + "?transport=tcp", user, pass, testRealm, nil, stageConnect, "certificate"},
		{"connect: turns certificate for another name", "turns:localhost:" + tlsPort + "?transport=tcp", user, pass, testRealm, good.pool, stageConnect, "certificate"},
		{"binding: a server that never answers", "turn:" + startFake(t, "mute") + "?transport=udp", user, pass, testRealm, nil, stageBinding, "no response"},
		{"allocate: wrong password", "turn:" + good.udp + "?transport=udp", user, "not-the-password", testRealm, nil, stageAllocate, "401"},
		{"allocate: unknown key tag", "turn:" + good.tcp + "?transport=tcp", "9999999999:ffff.probe", pass, testRealm, nil, stageAllocate, "401"},
		{"allocate: expired credentials", "turn:" + good.udp + "?transport=udp", expiredUser, expiredPass, testRealm, nil, stageAllocate, "401"},
		{"allocate: wrong realm", "turn:" + good.udp + "?transport=udp", user, pass, "other.realm", nil, stageAllocate, "realm"},
		{"permission: the server answers 403", "turn:" + startFake(t, "forbid") + "?transport=udp", user, pass, testRealm, nil, stagePermission, "403"},
		{"relay A->B: allocations that relay nothing", "turn:" + startFake(t, "drop") + "?transport=udp", user, pass, testRealm, nil, stageRelayAB, "did not come out"},
		{"relay B->A: relays one way only", "turn:" + startFake(t, "oneway") + "?transport=udp", user, pass, testRealm, nil, stageRelayBA, "did not come out"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := cli(t, c.roots, c.user, c.pass, "--server", c.server, "--realm", c.realm, "--timeout", "800ms")
			if err == nil {
				t.Fatalf("exit status 0\n%s", out)
			}
			line := strings.TrimSpace(out)
			if strings.Count(line, "\n") != 0 || !strings.HasPrefix(line, "FAIL "+c.server+" stage="+c.stage) {
				t.Fatalf("want one FAIL line at stage %q, got %q", c.stage, out)
			}
			if !strings.Contains(line, c.contains) {
				t.Errorf("line %q lacks %q", line, c.contains)
			}
		})
	}
}

func TestProbeMixedRunFailsOnAnyFail(t *testing.T) {
	r := startRelay(t, true)
	user, pass := r.mint(t, time.Now().Add(10*time.Minute))
	out, err := cli(t, nil, user, pass, "--realm", testRealm, "--timeout", "800ms",
		"--server", "turn:"+r.udp+"?transport=udp",
		"--server", "turn:127.0.0.1:1?transport=tcp")
	if err == nil || !strings.Contains(err.Error(), "1 of 2 servers failed") {
		t.Fatalf("err %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "PASS ") || !strings.HasPrefix(lines[1], "FAIL ") {
		t.Fatalf("got:\n%s", out)
	}
}

func TestParseServer(t *testing.T) {
	ok := []struct{ in, scheme, host, port, transport string }{
		{"turn:example.org:3478?transport=udp", "turn", "example.org", "3478", "udp"},
		{"turn:example.org:3478?transport=tcp", "turn", "example.org", "3478", "tcp"},
		{"turns:example.org:443?transport=tcp", "turns", "example.org", "443", "tcp"},
		{"turn:example.org", "turn", "example.org", "3478", "udp"},
		{"turns:example.org", "turns", "example.org", "5349", "tcp"},
		{"turn:[2001:db8::1]:3478?transport=udp", "turn", "2001:db8::1", "3478", "udp"},
		{"turn:[2001:db8::1]", "turn", "2001:db8::1", "3478", "udp"},
	}
	for _, c := range ok {
		got, err := parseServer(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got.Scheme != c.scheme || got.Host != c.host || got.Port != c.port || got.Transport != c.transport {
			t.Errorf("%q: got %+v", c.in, got)
		}
	}
	for _, bad := range []string{
		"", "example.org:3478", "stun:example.org:3478", "turn:", "turn://example.org:3478",
		"http://example.org", "turn:example.org:0", "turn:example.org:99999", "turn:example.org:abc",
		"turn:example.org:3478?transport=sctp", "turns:example.org:443?transport=udp",
		"turn:example.org:3478?foo=bar", "turn:user@example.org:3478", "turn:exa mple.org",
	} {
		if _, err := parseServer(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// notExist stands for "the error wraps fs.ErrNotExist": the wording is the OS's.
const notExist = "<fs.ErrNotExist>"

func TestUsageRefusals(t *testing.T) {
	dir := t.TempDir()
	mk := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
		return p
	}
	good := mk("good", "pw\n", 0o600)
	empty := mk("empty", " \n", 0o600)
	world := mk("world", "pw", 0o644)
	srv := "turn:127.0.0.1:3478?transport=udp"
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"nothing", nil, "--server, --username, --password-file, --realm"},
		{"no server", []string{"--username", "u", "--password-file", good, "--realm", "r"}, "--server"},
		{"no username", []string{"--server", srv, "--password-file", good, "--realm", "r"}, "--username"},
		{"no password file", []string{"--server", srv, "--username", "u", "--realm", "r"}, "--password-file"},
		{"no realm", []string{"--server", srv, "--username", "u", "--password-file", good}, "--realm"},
		{"bad server", []string{"--server", "nonsense", "--username", "u", "--password-file", good, "--realm", "r"}, "--server"},
		{"turns over udp", []string{"--server", "turns:h:443?transport=udp", "--username", "u", "--password-file", good, "--realm", "r"}, "DTLS"},
		{"password file missing", []string{"--server", srv, "--username", "u", "--password-file", filepath.Join(dir, "nope"), "--realm", "r"}, notExist},
		{"password file empty", []string{"--server", srv, "--username", "u", "--password-file", empty, "--realm", "r"}, "empty"},
		{"password file is a directory", []string{"--server", srv, "--username", "u", "--password-file", dir, "--realm", "r"}, "not a regular file"},
		{"zero timeout", []string{"--server", srv, "--username", "u", "--password-file", good, "--realm", "r", "--timeout", "0s"}, "--timeout"},
		{"stray argument", []string{"--server", srv, "--username", "u", "--password-file", good, "--realm", "r", "extra"}, "unknown command"},
	}
	if runtime.GOOS != "windows" {
		cases = append(cases, struct {
			name string
			args []string
			want string
		}{"password file world-readable", []string{"--server", srv, "--username", "u", "--password-file", world, "--realm", "r"}, "readable by everybody"})
	}
	for _, c := range cases {
		var out bytes.Buffer
		cmd := RootCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(c.args)
		err := cmd.Execute()
		if c.want == notExist {
			if !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s: err %v is not a missing-file error", c.name, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", c.name, err, c.want)
		}
		if strings.Contains(out.String(), "PASS") {
			t.Errorf("%s: printed a verdict: %q", c.name, out.String())
		}
	}
}

func TestMainExitsNonZeroOnRefusal(t *testing.T) {
	var code atomic.Int32
	osExit = func(c int) { code.Store(int32(c)) }
	defer func() { osExit = os.Exit }()
	os.Args = []string{"turnprobe"} // no flags: refused
	main()
	if code.Load() != 1 {
		t.Fatalf("exit code %d, want 1", code.Load())
	}
}
