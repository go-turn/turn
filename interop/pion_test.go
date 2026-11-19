// Package interop holds the interop judge: an independent TURN client,
// github.com/pion/turn/v4 (test-only dependency), drives the server.
package interop

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/go-turn/turn/server"
)

const (
	realm = "interop.test"
	user  = "alice"
	pass  = "s3cret-pw"
)

type harness struct {
	srv  *server.Server
	udp  string
	tcp  string
	peer *net.UDPConn
}

func startServer(t *testing.T, allowLoopback bool) *harness {
	t.Helper()
	cfg := server.Config{
		Realm:   realm,
		Auth:    func(u string) (string, bool) { return pass, u == user },
		RelayIP: netip.MustParseAddr("127.0.0.1"),
	}
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServePacketConn(pc)
	go srv.ServeListener(ln)

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	go func() { // UDP echo peer
		buf := make([]byte, 65535)
		for {
			n, from, err := peer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			peer.WriteToUDP(buf[:n], from)
		}
	}()
	return &harness{srv: srv, udp: pc.LocalAddr().String(), tcp: ln.Addr().String(), peer: peer}
}

func newClient(t *testing.T, serverAddr string, conn net.PacketConn) *turn.Client {
	t.Helper()
	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: serverAddr,
		TURNServerAddr: serverAddr,
		Conn:           conn,
		Username:       user,
		Password:       pass,
		Realm:          realm,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// roundTrip writes payload to the peer through the relay until the echo
// arrives (the first packets race the permission and channel set-up).
func roundTrip(t *testing.T, relay net.PacketConn, peer net.Addr, payload []byte) bool {
	t.Helper()
	buf := make([]byte, 65535)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := relay.WriteTo(payload, peer); err != nil {
			t.Fatalf("relay write: %v", err)
		}
		relay.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		n, from, err := relay.ReadFrom(buf)
		if err != nil {
			continue
		}
		if from.String() != peer.String() {
			t.Fatalf("data from %v, want %v", from, peer)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("echo differs: %d bytes", n)
		}
		return true
	}
	return false
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPionBinding(t *testing.T) {
	h := startServer(t, false)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := newClient(t, h.udp, conn)
	mapped, err := c.SendBindingRequest()
	if err != nil {
		t.Fatal(err)
	}
	if mapped.String() != conn.LocalAddr().String() {
		t.Fatalf("mapped %v, local %v", mapped, conn.LocalAddr())
	}
}

// TestPionAllocatePermissionChannelRoundTrip is the judge: pion allocates,
// permits the echo peer, binds a channel and round-trips data through the
// relay, over UDP and over TCP.
func TestPionAllocatePermissionChannelRoundTrip(t *testing.T) {
	for _, tc := range []string{"udp", "tcp"} {
		t.Run(tc, func(t *testing.T) {
			h := startServer(t, true)
			var conn net.PacketConn
			serverAddr := h.udp
			if tc == "udp" {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				conn = pc
			} else {
				nc, err := net.Dial("tcp", h.tcp)
				if err != nil {
					t.Fatal(err)
				}
				conn = turn.NewSTUNConn(nc)
				serverAddr = h.tcp
			}
			defer conn.Close()
			c := newClient(t, serverAddr, conn)
			relay, err := c.Allocate()
			if err != nil {
				t.Fatalf("allocate: %v", err)
			}
			ra := relay.LocalAddr().(*net.UDPAddr)
			if !ra.IP.Equal(net.IPv4(127, 0, 0, 1)) || ra.Port == 0 {
				t.Fatalf("relayed address %v", ra)
			}
			if got := h.srv.Stats().Allocations; got != 1 {
				t.Fatalf("%d allocations", got)
			}
			peer := h.peer.LocalAddr()
			if !roundTrip(t, relay, peer, []byte("through the relay")) {
				t.Fatal("no echo through the relay")
			}
			// pion binds a channel after the first Send; once the server
			// has accepted it, traffic runs as ChannelData.
			waitFor(t, "ChannelBind", func() bool { return h.srv.Stats().ChannelBinds > 0 })
			big := bytes.Repeat([]byte("0123456789"), 120) // 1200 bytes
			if !roundTrip(t, relay, peer, big) {
				t.Fatal("no echo over the bound channel")
			}
			// The counters are bumped after the socket write, so the echo
			// can be read before the count; wait for it.
			waitFor(t, "relay counters", func() bool {
				st := h.srv.Stats()
				return st.PacketsToPeer >= 2 && st.PacketsToClient >= 2
			})
			// Closing the relay sends Refresh with LIFETIME 0.
			if err := relay.Close(); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "allocation deletion", func() bool { return h.srv.Stats().Allocations == 0 })
		})
	}
}

// TestPionThroughProxyProtocol puts a proxy between pion's TCP client and the
// server, as Caddy (caddy-l4 with proxy_protocol v2) does: the proxy prepends
// a v2 header naming the real client, and the server, which trusts it, uses
// that address.
func TestPionThroughProxyProtocol(t *testing.T) {
	const realClient = "198.51.100.7:4242"
	srv, err := server.New(server.Config{
		Realm:             realm,
		Auth:              func(u string) (string, bool) { return pass, u == user },
		RelayIP:           netip.MustParseAddr("127.0.0.1"),
		AllowPeers:        []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		ProxyProtocolFrom: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeListener(backend)

	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { front.Close() })
	go func() { // the proxy
		for {
			c, err := front.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b, err := net.Dial("tcp", backend.Addr().String())
				if err != nil {
					return
				}
				defer b.Close()
				hdr := server.AppendProxyHeaderV2(nil, netip.MustParseAddrPort(realClient),
					netip.MustParseAddrPort(backend.Addr().String()))
				if _, err := b.Write(hdr); err != nil {
					return
				}
				go io.Copy(b, c)
				io.Copy(c, b)
			}()
		}
	}()

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := peer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			peer.WriteToUDP(buf[:n], from)
		}
	}()

	nc, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn := turn.NewSTUNConn(nc)
	defer conn.Close()
	c := newClient(t, front.Addr().String(), conn)
	mapped, err := c.SendBindingRequest()
	if err != nil {
		t.Fatal(err)
	}
	if mapped.String() != realClient {
		t.Fatalf("server saw the client as %v, want the header's %s", mapped, realClient)
	}
	relay, err := c.Allocate()
	if err != nil {
		t.Fatalf("allocate through the proxy: %v", err)
	}
	defer relay.Close()
	if !roundTrip(t, relay, peer.LocalAddr(), []byte("via proxy protocol")) {
		t.Fatal("no echo through the proxied relay")
	}
}

// TestPionRefusedPeer shows the default policy through an independent
// client: the echo peer is on loopback, so nothing reaches it.
func TestPionRefusedPeer(t *testing.T) {
	h := startServer(t, false)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := newClient(t, h.udp, conn)
	relay, err := c.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	buf := make([]byte, 1500)
	for i := 0; i < 5; i++ {
		relay.WriteTo([]byte("leak"), h.peer.LocalAddr())
		relay.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if n, _, err := relay.ReadFrom(buf); err == nil {
			t.Fatalf("got %d bytes back from a refused peer", n)
		}
	}
	if st := h.srv.Stats(); st.PacketsToPeer != 0 || st.ChannelBinds != 0 {
		t.Fatalf("traffic reached a refused peer: %+v", st)
	}
}
