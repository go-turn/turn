package server

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/go-turn/turn/stun"
)

var (
	pxSrc4 = netip.MustParseAddrPort("198.51.100.7:4242")
	pxDst4 = netip.MustParseAddrPort("203.0.113.5:3478")
	pxSrc6 = netip.MustParseAddrPort("[2001:db8::7]:4242")
)

// v2 builds a raw v2 header: verCmd, famProto, then the address block.
func v2(verCmd, famProto byte, block []byte) []byte {
	b := append([]byte(nil), proxySig...)
	b = append(b, verCmd, famProto, byte(len(block)>>8), byte(len(block)))
	return append(b, block...)
}

func TestReadProxyHeaderAccepts(t *testing.T) {
	v4 := AppendProxyHeaderV2(nil, pxSrc4, pxDst4)
	v6 := AppendProxyHeaderV2(nil, pxSrc6, netip.MustParseAddrPort("[2001:db8::1]:3478"))
	tlv := append(bytes.Clone(v4[16:]), 0x04, 0x00, 0x02, 'h', 'i') // a TLV after the block
	cases := []struct {
		name  string
		in    []byte
		local bool
		src   netip.AddrPort
	}{
		{"v2 tcp4", v4, false, pxSrc4},
		{"v2 tcp6", v6, false, pxSrc6},
		{"v2 tcp4 with TLV", v2(0x21, 0x11, tlv), false, pxSrc4},
		{"v2 LOCAL", v2(0x20, 0x00, nil), true, netip.AddrPort{}},
		{"v2 LOCAL with block", v2(0x20, 0x11, v4[16:]), true, netip.AddrPort{}},
		{"v2 PROXY AF_UNSPEC", v2(0x21, 0x00, nil), true, netip.AddrPort{}},
		{"v1 tcp4", []byte("PROXY TCP4 198.51.100.7 203.0.113.5 4242 3478\r\n"), false, pxSrc4},
		{"v1 tcp6", []byte("PROXY TCP6 2001:db8::7 2001:db8::1 4242 3478\r\n"), false, pxSrc6},
		{"v1 UNKNOWN", []byte("PROXY UNKNOWN\r\n"), true, netip.AddrPort{}},
	}
	for _, c := range cases {
		// Bytes after the header must stay unread: they are the client's stream.
		r := bytes.NewReader(append(bytes.Clone(c.in), "TAIL"...))
		h, err := readProxyHeader(r)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if h.Local != c.local || h.Src != c.src {
			t.Errorf("%s: got %+v", c.name, h)
		}
		if r.Len() != 4 {
			t.Errorf("%s: %d bytes left, want exactly the 4 after the header", c.name, r.Len())
		}
	}
}

func TestReadProxyHeaderRefuses(t *testing.T) {
	v4 := AppendProxyHeaderV2(nil, pxSrc4, pxDst4)
	blk := v4[16:]
	mut := func(i int, v byte) []byte { b := bytes.Clone(v4); b[i] = v; return b }
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrProxyHeader},
		{"STUN message", []byte("\x00\x01\x00\x00\x21\x12\xa4B123456789012"), ErrProxyHeader},
		{"bad signature byte", mut(8, 0xff), ErrProxyHeader},
		{"truncated signature", v4[:9], ErrProxyHeader},
		{"truncated fixed part", v4[:15], ErrProxyHeader},
		{"truncated block", v4[:len(v4)-1], ErrProxyHeader},
		{"version 1", mut(12, 0x11), ErrProxyHeader},
		{"version 3", mut(12, 0x31), ErrProxyHeader},
		{"command 2", mut(12, 0x22), ErrProxyHeader},
		{"command 15", mut(12, 0x2f), ErrProxyHeader},
		{"UDP over IPv4", v2(0x21, 0x12, blk), ErrProxyFamily},
		{"UDP over IPv6", v2(0x21, 0x22, make([]byte, 36)), ErrProxyFamily},
		{"UNIX stream", v2(0x21, 0x31, make([]byte, 216)), ErrProxyFamily},
		{"UNIX datagram", v2(0x21, 0x32, make([]byte, 216)), ErrProxyFamily},
		{"unknown family", v2(0x21, 0x41, blk), ErrProxyFamily},
		{"unknown transport", v2(0x21, 0x13, blk), ErrProxyFamily},
		{"AF_INET block too short", v2(0x21, 0x11, blk[:11]), ErrProxyHeader},
		{"AF_INET6 block too short", v2(0x21, 0x21, make([]byte, 35)), ErrProxyHeader},
		{"block above the bound", v2(0x21, 0x11, make([]byte, maxProxyBlock+1)), ErrProxyHeader},
		{"claimed length beyond data", append(bytes.Clone(v4[:14]), 0xff, 0xff), ErrProxyHeader},
		{"source port 0", AppendProxyHeaderV2(nil, netip.MustParseAddrPort("198.51.100.7:0"), pxDst4), ErrProxyHeader},
		{"source 0.0.0.0", AppendProxyHeaderV2(nil, netip.MustParseAddrPort("0.0.0.0:9"), pxDst4), ErrProxyHeader},
		{"source multicast", AppendProxyHeaderV2(nil, netip.MustParseAddrPort("224.0.0.1:9"), pxDst4), ErrProxyHeader},
		{"source ::", AppendProxyHeaderV2(nil, netip.MustParseAddrPort("[::]:9"), netip.MustParseAddrPort("[::1]:9")), ErrProxyHeader},
		{"v1 bare LF", []byte("PROXY TCP4 198.51.100.7 203.0.113.5 4242 3478\n"), ErrProxyHeader},
		{"v1 no terminator within 107", append([]byte("PROXY TCP4 198.51.100.7 203.0.113.5 4242 3478 "), bytes.Repeat([]byte("x"), 200)...), ErrProxyHeader},
		{"v1 unknown protocol", []byte("PROXY UDP4 198.51.100.7 203.0.113.5 4242 3478\r\n"), ErrProxyHeader},
		{"v1 family mismatch", []byte("PROXY TCP4 2001:db8::7 203.0.113.5 4242 3478\r\n"), ErrProxyHeader},
		{"v1 leading-zero port", []byte("PROXY TCP4 198.51.100.7 203.0.113.5 04242 3478\r\n"), ErrProxyHeader},
		{"v1 port above 65535", []byte("PROXY TCP4 198.51.100.7 203.0.113.5 65536 3478\r\n"), ErrProxyHeader},
		{"v1 missing field", []byte("PROXY TCP4 198.51.100.7 203.0.113.5 4242\r\n"), ErrProxyHeader},
		{"v1 truncated", []byte("PROXY TCP4 198.51.100.7"), ErrProxyHeader},
	}
	for _, c := range cases {
		if _, err := readProxyHeader(bytes.NewReader(c.in)); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

// proxied starts a server that trusts loopback as a proxy.
func proxied(t *testing.T, withTCP bool, mut func(*Config)) *env {
	return start(t, withTCP, func(c *Config) {
		c.ProxyProtocolFrom = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
		c.HandshakeTimeout = 400 * time.Millisecond
		if mut != nil {
			mut(c)
		}
	})
}

func rawStream(t *testing.T, to netip.AddrPort) *client {
	t.Helper()
	c, err := net.Dial("tcp", to.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &client{t: t, conn: c, stream: true, user: "alice", pass: testUsers["alice"]}
}

func mapped(t *testing.T, c *client) netip.AddrPort {
	t.Helper()
	r := c.do(stun.New(stun.ClassRequest, stun.MethodBinding))
	mustSuccess(t, r)
	a, err := r.Addr(stun.AttrXORMappedAddress)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// closed reports that the server ended the connection without answering.
func closed(c *client, within time.Duration) bool {
	c.conn.SetReadDeadline(time.Now().Add(within))
	n, err := c.conn.Read(make([]byte, 64))
	ne, isNet := err.(net.Error)
	return n == 0 && err != nil && !(isNet && ne.Timeout())
}

func TestProxyHeaderSetsClientAddress(t *testing.T) {
	e := proxied(t, true, nil)
	for name, hdr := range map[string][]byte{
		"v2 tcp4": AppendProxyHeaderV2(nil, pxSrc4, pxDst4),
		"v2 tcp6": AppendProxyHeaderV2(nil, pxSrc6, netip.MustParseAddrPort("[2001:db8::1]:3478")),
		"v1":      []byte("PROXY TCP4 198.51.100.7 203.0.113.5 4242 3478\r\n"),
	} {
		c := rawStream(t, e.tcp)
		c.send(hdr)
		want := pxSrc4
		if name == "v2 tcp6" {
			want = pxSrc6
		}
		if got := mapped(t, c); got != want {
			t.Errorf("%s: XOR-MAPPED-ADDRESS %v, want the header's %v", name, got, want)
		}
	}
}

func TestProxyHeaderAllocateReportsHeaderAddress(t *testing.T) {
	e := proxied(t, true, nil)
	c := rawStream(t, e.tcp)
	c.send(AppendProxyHeaderV2(nil, pxSrc4, pxDst4))
	r := c.allocate(nil)
	relayedOf(t, r)
	got, err := r.Addr(stun.AttrXORMappedAddress)
	if err != nil || got != pxSrc4 {
		t.Fatalf("Allocate XOR-MAPPED-ADDRESS %v (%v), want %v", got, err, pxSrc4)
	}
	if e.srv.Stats().Allocations != 1 {
		t.Fatal("no allocation")
	}
}

func TestProxyHeaderOverTLSPrecedesClientHello(t *testing.T) {
	e := proxied(t, true, nil)
	raw, err := net.Dial("tcp", e.tls.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	raw.Write(AppendProxyHeaderV2(nil, pxSrc4, pxDst4))
	tc := tls.Client(raw, &tls.Config{RootCAs: e.cert, ServerName: "turn.test"})
	c := &client{t: t, conn: tc, stream: true}
	if got := mapped(t, c); got != pxSrc4 {
		t.Fatalf("mapped %v, want %v", got, pxSrc4)
	}
}

func TestProxyLocalCommandUsesRealAddress(t *testing.T) {
	e := proxied(t, true, nil)
	for name, hdr := range map[string][]byte{
		"v2 LOCAL":   v2(0x20, 0x00, nil),
		"v1 UNKNOWN": []byte("PROXY UNKNOWN\r\n"),
	} {
		c := rawStream(t, e.tcp)
		c.send(hdr)
		want := netip.MustParseAddrPort(c.conn.LocalAddr().String())
		if got := mapped(t, c); got != want {
			t.Errorf("%s: mapped %v, want the real %v", name, got, want)
		}
	}
}

func TestProxyRefusals(t *testing.T) {
	e := proxied(t, true, nil)
	v4 := AppendProxyHeaderV2(nil, pxSrc4, pxDst4)
	binding, _ := stun.New(stun.ClassRequest, stun.MethodBinding).Encode()
	cases := map[string][]byte{
		"trusted source, no header (STUN)":    binding,
		"trusted source, garbage":             []byte("GET / HTTP/1.1\r\n\r\n"),
		"UNIX family":                         v2(0x21, 0x31, make([]byte, 216)),
		"UDP family":                          v2(0x21, 0x12, v4[16:]),
		"unknown family":                      v2(0x21, 0x41, v4[16:]),
		"version 1 in the binary form":        v2(0x11, 0x11, v4[16:]),
		"unknown command":                     v2(0x22, 0x11, v4[16:]),
		"block length above the bound":        v2(0x21, 0x11, make([]byte, maxProxyBlock+1)),
		"AF_INET block too short":             v2(0x21, 0x11, v4[16:27]),
		"source port 0":                       AppendProxyHeaderV2(nil, netip.MustParseAddrPort("198.51.100.7:0"), pxDst4),
		"header then nothing, truncated":      v4[:20],
		"v1 line without terminator":          bytes.Repeat([]byte("PROXY TCP4 "), 20),
		"v1 line, bare LF":                    []byte("PROXY TCP4 198.51.100.7 203.0.113.5 4242 3478\n"),
		"v2 signature then STUN, no header":   append(bytes.Clone(proxySig), binding...),
		"header claims unspecified source":    AppendProxyHeaderV2(nil, netip.MustParseAddrPort("0.0.0.0:9"), pxDst4),
		"valid header, then a malformed STUN": append(bytes.Clone(v4), 0, 1, 0, 3),
	}
	before := e.srv.Stats().Allocations
	for name, in := range cases {
		c := rawStream(t, e.tcp)
		c.send(in)
		if !closed(c, 3*time.Second) {
			t.Errorf("%s: connection not closed without an answer", name)
		}
	}
	// The same refusals apply on the TLS listener (a bad header closes it
	// before any handshake bytes are read).
	c := rawStream(t, e.tls)
	c.send(v2(0x21, 0x31, make([]byte, 216)))
	if !closed(c, 3*time.Second) {
		t.Error("TLS: bad header not refused")
	}
	if e.srv.Stats().Allocations != before {
		t.Error("an allocation appeared")
	}
}

func TestProxyHeaderStallIsCut(t *testing.T) {
	e := proxied(t, true, nil)
	c := rawStream(t, e.tcp)
	c.send(proxySig[:5]) // a partial header, then silence
	start := time.Now()
	if !closed(c, 3*time.Second) {
		t.Fatal("stalled header held the connection open")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("cut after %v, want about the 400 ms handshake timeout", d)
	}
	// A claimed 512-byte block that never arrives is cut the same way.
	c2 := rawStream(t, e.tcp)
	c2.send(v2(0x21, 0x11, nil)[:14])
	c2.send([]byte{0x02, 0x00})
	if !closed(c2, 3*time.Second) {
		t.Fatal("stalled block held the connection open")
	}
}

func TestProxyHeaderFromUntrustedSourceIsNeverHonoured(t *testing.T) {
	// Only 10.0.0.0/8 is trusted; the test client is on 127.0.0.1.
	e := proxied(t, true, func(c *Config) {
		c.ProxyProtocolFrom = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	})
	binding, _ := stun.New(stun.ClassRequest, stun.MethodBinding).Encode()
	hdr := AppendProxyHeaderV2(nil, pxSrc4, pxDst4)
	for name, in := range map[string][]byte{
		"v2 header then STUN": append(bytes.Clone(hdr), binding...),
		"v1 header then STUN": append([]byte("PROXY TCP4 198.51.100.7 203.0.113.5 4242 3478\r\n"), binding...),
		"v2 LOCAL header":     append(v2(0x20, 0x00, nil), binding...),
	} {
		c := rawStream(t, e.tcp)
		c.send(in)
		if !closed(c, 3*time.Second) {
			t.Errorf("%s: an untrusted source's header was read as something", name)
		}
	}
	// Over TLS the header cannot be a ClientHello either.
	c := rawStream(t, e.tls)
	c.send(append(bytes.Clone(hdr), binding...))
	if !closed(c, 3*time.Second) {
		t.Error("TLS: untrusted header not refused")
	}
	// A direct client from the same untrusted source is served as usual,
	// with its real address.
	d := rawStream(t, e.tcp)
	want := netip.MustParseAddrPort(d.conn.LocalAddr().String())
	if got := mapped(t, d); got != want {
		t.Fatalf("direct client mapped %v, want %v", got, want)
	}
}

func TestProxyOffByDefault(t *testing.T) {
	// With ProxyProtocolFrom empty a header is just bytes the STUN framer
	// refuses.
	e := start(t, true, nil)
	c := rawStream(t, e.tcp)
	c.send(AppendProxyHeaderV2(nil, pxSrc4, pxDst4))
	if !closed(c, 3*time.Second) {
		t.Fatal("header honoured while the feature is off")
	}
}

func TestProxyConfigValidation(t *testing.T) {
	for name, p := range map[string]netip.Prefix{
		"zero":   {},
		"mapped": netip.MustParsePrefix("::ffff:127.0.0.0/104"),
	} {
		s, err := New(Config{Realm: "r", Auth: testAuth, RelayIP: netip.MustParseAddr("127.0.0.1"),
			ProxyProtocolFrom: []netip.Prefix{p}})
		if err == nil {
			s.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzProxyHeader(f *testing.F) {
	f.Add(AppendProxyHeaderV2(nil, pxSrc4, pxDst4))
	f.Add(AppendProxyHeaderV2(nil, pxSrc6, netip.MustParseAddrPort("[2001:db8::1]:1")))
	f.Add(v2(0x20, 0x00, nil))
	f.Add(v2(0x21, 0x31, make([]byte, 216)))
	f.Add([]byte("PROXY TCP4 198.51.100.7 203.0.113.5 4242 3478\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		h, err := readProxyHeader(r)
		if err != nil {
			return
		}
		if consumed := len(b) - r.Len(); consumed > 16+maxProxyBlock && consumed > maxProxyV1 {
			t.Fatalf("read %d bytes, beyond the bounds", consumed)
		}
		if !h.Local {
			a := h.Src.Addr()
			if !h.Src.IsValid() || a.IsUnspecified() || a.IsMulticast() || h.Src.Port() == 0 || a.Is4In6() {
				t.Fatalf("accepted source %v", h.Src)
			}
		}
	})
}
