package server

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/go-turn/turn/stun"
)

// Two clients relaying to each other through one server is the normal WebRTC
// case behind a symmetric NAT: A's peer is B's relayed address, which is this
// server's own IP. None of these tests allowlists that address.

func twoAllocations(t *testing.T, e *env, a, b *client) (relA, relB netip.AddrPort) {
	t.Helper()
	relA = relayedOf(t, a.allocate(nil))
	relB = relayedOf(t, b.allocate(nil))
	return
}

func TestRelayToRelayExchangesDataBothWays(t *testing.T) {
	e := start(t, true, nil) // RelayIP 127.0.0.1, no AllowPeers
	// Across transports: A over UDP, B over TCP.
	a, b := dialUDP(t, e.udp), dialTCP(t, e.tcp)
	relA, relB := twoAllocations(t, e, a, b)
	mustSuccess(t, a.permit(relB))
	mustSuccess(t, b.permit(relA))

	a.sendInd(relB, []byte("a to b"))
	peer, _, got, ok := b.data(2 * time.Second)
	if !ok || string(got) != "a to b" || peer != relA {
		t.Fatalf("B got %q from %v (ok=%v), want %q from %v", got, peer, ok, "a to b", relA)
	}
	b.sendInd(relA, []byte("b to a"))
	peer, _, got, ok = a.data(2 * time.Second)
	if !ok || string(got) != "b to a" || peer != relB {
		t.Fatalf("A got %q from %v (ok=%v), want %q from %v", got, peer, ok, "b to a", relB)
	}

	// The same through channels.
	mustSuccess(t, a.bind(0x4000, relB))
	mustSuccess(t, b.bind(0x4001, relA))
	a.sendChan(0x4000, []byte("chan a to b"))
	_, ch, got, ok := b.data(2 * time.Second)
	if !ok || ch != 0x4001 || string(got) != "chan a to b" {
		t.Fatalf("B got channel %#x %q (ok=%v)", ch, got, ok)
	}
	b.sendChan(0x4001, []byte("chan b to a"))
	_, ch, got, ok = a.data(2 * time.Second)
	if !ok || ch != 0x4000 || string(got) != "chan b to a" {
		t.Fatalf("A got channel %#x %q (ok=%v)", ch, got, ok)
	}
}

func TestRelayToRelayNeedsThePeersPermission(t *testing.T) {
	e := start(t, false, nil)
	a, b := dialUDP(t, e.udp), dialUDP(t, e.udp)
	_, relB := twoAllocations(t, e, a, b)
	mustSuccess(t, a.permit(relB)) // B never permits A
	a.sendInd(relB, []byte("unwanted"))
	if _, _, got, ok := b.data(300 * time.Millisecond); ok {
		t.Fatalf("B received %q without having permitted A", got)
	}
}

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort().Port()
}

func TestOwnAddressRefusedExceptAtALiveRelayedPort(t *testing.T) {
	e := start(t, true, nil)
	a := dialUDP(t, e.udp)
	mustSuccess(t, a.allocate(nil))
	own := netip.MustParseAddr("127.0.0.1")
	cases := []struct {
		name string
		peer netip.AddrPort
	}{
		{"a relay-range port with no live allocation", netip.AddrPortFrom(own, freeUDPPort(t))},
		{"the server's own UDP listener", netip.AddrPortFrom(own, e.udp.Port())},
		{"the server's own TCP listener", netip.AddrPortFrom(own, e.tcp.Port())},
		{"the server's own TLS listener", netip.AddrPortFrom(own, e.tls.Port())},
		{"ssh", netip.AddrPortFrom(own, 22)},
		{"https", netip.AddrPortFrom(own, 443)},
		{"port 1", netip.AddrPortFrom(own, 1)},
	}
	for _, c := range cases {
		if got := errCode(t, a.permit(c.peer)); got != 403 {
			t.Errorf("CreatePermission %s: %d, want 403", c.name, got)
		}
		if got := errCode(t, a.bind(0x4010, c.peer)); got != 403 {
			t.Errorf("ChannelBind %s: %d, want 403", c.name, got)
		}
	}
}

func TestOtherRefusalsStayRefused(t *testing.T) {
	e := start(t, true, nil)
	a := dialUDP(t, e.udp)
	mustSuccess(t, a.allocate(nil))
	for _, p := range []string{
		"127.0.0.2:5000", "10.0.0.1:5000", "192.168.1.1:5000", "169.254.169.254:80",
		"100.64.0.1:5000", "224.0.0.1:5000",
	} {
		if got := errCode(t, a.permit(netip.MustParseAddrPort(p))); got != 403 {
			t.Errorf("%s: %d, want 403", p, got)
		}
	}
}

// A permission covers an IP, not a port: once A may reach B's relayed port it
// must still not reach any other port of the same address.
func TestPermissionForOwnIPDoesNotOpenOtherPorts(t *testing.T) {
	e := start(t, true, nil)
	a, b := dialUDP(t, e.udp), dialUDP(t, e.udp)
	relA, relB := twoAllocations(t, e, a, b)
	mustSuccess(t, a.permit(relB))

	// A service of the host on its own address, standing in for sshd.
	svc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	svcAddr := svc.LocalAddr().(*net.UDPAddr).AddrPort()

	before := e.srv.Stats()
	a.sendInd(svcAddr, []byte("knock"))
	a.sendInd(netip.AddrPortFrom(svcAddr.Addr(), e.udp.Port()), []byte("to the TURN port itself"))
	svc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := svc.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatalf("the service received %d bytes through the relay", n)
	}
	if got := e.srv.Stats(); got.PacketsToPeer != before.PacketsToPeer || got.Dropped < before.Dropped+2 {
		t.Fatalf("stats %+v -> %+v: want both sends dropped and none relayed", before, got)
	}

	// And the other way: a process of the host sending to A's relayed port from
	// the server's own IP is not a peer, whatever A has permitted.
	stray, err := net.Dial("udp", relA.String())
	if err != nil {
		t.Fatal(err)
	}
	defer stray.Close()
	stray.Write([]byte("from another process of the host"))
	if _, _, got, ok := a.data(300 * time.Millisecond); ok {
		t.Fatalf("A received %q from a process of the host", got)
	}
}

// An allocation that expires after the permission to its relayed port was
// made is no longer a peer: the datagram is dropped, not sent to the socket.
func TestRelayToExpiredAllocationIsDropped(t *testing.T) {
	e := start(t, true, nil)
	a, b := dialUDP(t, e.udp), dialUDP(t, e.udp)
	relA := relayedOf(t, a.allocate(nil))
	relB := relayedOf(t, b.allocate(func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 60) }))
	mustSuccess(t, a.permit(relB))
	mustSuccess(t, b.permit(relA))

	a.sendInd(relB, []byte("alive"))
	if _, _, got, ok := b.data(2 * time.Second); !ok || string(got) != "alive" {
		t.Fatalf("B got %q (ok=%v) while its allocation was live", got, ok)
	}

	e.clk.Advance(61 * time.Second) // B's allocation is over; A's, and A's permission, are not
	before := e.srv.Stats()
	a.sendInd(relB, []byte("too late"))
	if _, _, got, ok := b.data(300 * time.Millisecond); ok {
		t.Fatalf("B received %q after its allocation expired", got)
	}
	if got := e.srv.Stats(); got.PacketsToPeer != before.PacketsToPeer || got.Dropped <= before.Dropped {
		t.Fatalf("stats %+v -> %+v: want the datagram dropped and not relayed", before, got)
	}
	// B's relayed port is no longer one A can be given.
	if got := errCode(t, a.permit(relB)); got != 403 {
		t.Fatalf("CreatePermission for the expired allocation: %d, want 403", got)
	}
}
