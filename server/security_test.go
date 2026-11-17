package server

import (
	"net/netip"
	"testing"

	"github.com/go-turn/turn/stun"
)

// refused lists peer addresses the relay must answer 403 for by default.
var refused = []string{
	"127.0.0.1:5000", "127.255.255.254:1", "0.0.0.1:1", "0.255.255.255:9",
	"10.0.0.1:1", "172.16.0.1:1", "172.31.255.255:1", "192.168.1.1:1",
	"100.64.0.1:1", "100.127.255.254:1",
	"169.254.169.254:80", "169.254.0.1:1",
	"224.0.0.1:1", "239.255.255.250:1", "255.255.255.255:1", "240.0.0.1:1",
	"[::1]:1", "[::]:1", "[fc00::1]:1", "[fd12:3456::1]:1", "[fe80::1]:1", "[ff02::1]:1",
	"[::ffff:127.0.0.1]:1", "[::ffff:10.0.0.1]:1", "[::ffff:169.254.169.254]:80",
	"[::ffff:192.168.0.1]:1", "[::ffff:100.64.0.1]:1", "[::ffff:0.0.0.1]:1",
	"[64:ff9b::7f00:1]:1", "[2002:7f00:1::]:1", "[::7f00:1]:1",
	"203.0.113.7:3478", // the server's own address, set through OwnAddrs below
	"203.0.113.9:0",    // port 0
}

func ownCfg(c *Config) { c.OwnAddrs = []netip.Addr{netip.MustParseAddr("203.0.113.7")} }

func TestDefaultPolicyRefusesCreatePermission(t *testing.T) {
	e := start(t, false, ownCfg)
	c := dialUDP(t, e.udp)
	relayedOf(t, c.allocate(nil))
	for _, p := range refused {
		peer := netip.MustParseAddrPort(p)
		code := errCode(t, c.permit(peer))
		// IPv6 peers on an IPv4 relay may be answered 403 (policy) or
		// 443 (family); the policy check runs first, so it is always 403.
		if code != stun.CodeForbidden {
			t.Errorf("CreatePermission %s: %d, want 403", p, code)
		}
	}
	// One forbidden address among allowed ones refuses the whole request.
	if errCode(t, c.permit(netip.MustParseAddrPort("198.51.100.1:1"), netip.MustParseAddrPort("10.0.0.1:1"))) != 403 {
		t.Fatal("mixed request not refused")
	}
	// A public address is allowed, so the refusal is not blanket.
	mustSuccess(t, c.permit(netip.MustParseAddrPort("198.51.100.1:1")))
}

func TestDefaultPolicyRefusesChannelBind(t *testing.T) {
	e := start(t, false, ownCfg)
	c := dialUDP(t, e.udp)
	relayedOf(t, c.allocate(nil))
	for i, p := range refused {
		peer := netip.MustParseAddrPort(p)
		if code := errCode(t, c.bind(uint16(0x4000+i), peer)); code != stun.CodeForbidden {
			t.Errorf("ChannelBind %s: %d, want 403", p, code)
		}
	}
	mustSuccess(t, c.bind(0x4800, netip.MustParseAddrPort("198.51.100.1:1")))
}

func TestDefaultPolicyDropsSendToLoopback(t *testing.T) {
	// Even with a live permission for a public address, a Send to loopback
	// is not relayed: no listener on 127.0.0.1 sees a byte.
	e := start(t, false, nil)
	peer := echoPeer(t) // on 127.0.0.1, which the default policy refuses
	c := dialUDP(t, e.udp)
	relayedOf(t, c.allocate(nil))
	if errCode(t, c.permit(peer)) != 403 {
		t.Fatal("loopback permission accepted")
	}
	c.sendInd(peer, []byte("leak"))
	c.sendChan(0x4001, []byte("leak"))
	if _, _, _, ok := c.data(300e6); ok {
		t.Fatal("echo from a refused peer")
	}
	if got := e.srv.Stats().PacketsToPeer; got != 0 {
		t.Fatalf("%d packets reached a refused peer", got)
	}
}

func TestAllowlistReenablesOnlyItsRange(t *testing.T) {
	e := start(t, false, loopbackAllow)
	c := dialUDP(t, e.udp)
	relayedOf(t, c.allocate(nil))
	mustSuccess(t, c.permit(netip.MustParseAddrPort("127.0.0.1:5000")))
	mustSuccess(t, c.permit(netip.MustParseAddrPort("[::ffff:127.0.0.1]:5000")))
	for _, p := range []string{"10.0.0.1:1", "169.254.169.254:80", "192.168.0.1:1"} {
		if errCode(t, c.permit(netip.MustParseAddrPort(p))) != 403 {
			t.Errorf("%s accepted with only 127/8 allowlisted", p)
		}
	}
}

func TestPolicyTable(t *testing.T) {
	p := newPolicy(nil, []netip.Addr{netip.MustParseAddr("203.0.113.7")})
	for _, s := range refused {
		ap := netip.MustParseAddrPort(s)
		a := ap.Addr()
		if ap.Port() == 0 {
			continue // refused for its port, not its address
		}
		if p.permitted(a) {
			t.Errorf("permitted(%s) = true", a)
		}
	}
	for _, s := range []string{"8.8.8.8", "198.51.100.1", "1.1.1.1", "172.32.0.1", "172.15.255.255", "100.128.0.1",
		"2606:4700:4700::1111", "[::ffff:8.8.8.8]", "2a00:1450::1"} {
		a := netip.MustParseAddr(s[:0] + trimBrackets(s))
		if !p.permitted(a) {
			t.Errorf("permitted(%s) = false", a)
		}
	}
	if p.permitted(netip.Addr{}) {
		t.Error("zero address permitted")
	}
	// Interface addresses of the host are own addresses.
	al := newPolicy([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, nil)
	if !al.permitted(netip.MustParseAddr("127.0.0.1")) {
		t.Error("allowlist ignored")
	}
}

func trimBrackets(s string) string {
	if len(s) > 0 && s[0] == '[' {
		return s[1 : len(s)-1]
	}
	return s
}
