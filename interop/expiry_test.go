package interop

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"github.com/go-turn/turn/creds"
	"github.com/go-turn/turn/server"
)

type fakeClock struct{ off atomic.Int64 }

func (c *fakeClock) Now() time.Time          { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *fakeClock) Advance(d time.Duration) { c.off.Add(int64(d)) }

func echoPeerAt(t *testing.T) *net.UDPConn {
	t.Helper()
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
	return peer
}

func pionWith(t *testing.T, addr, username, password string) *turn.Client {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: addr, TURNServerAddr: addr, Conn: conn,
		Username: username, Password: password, Realm: realm,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
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

// TestPionAllocationOutlivesItsCredential: pion holds a relayed call across the
// expiry of the credential that opened it (a fake clock moves the server 61
// minutes on): it still permits a new peer, binds a channel, relays, and closes
// its allocation, while the same expired credential cannot allocate anew.
func TestPionAllocationOutlivesItsCredential(t *testing.T) {
	clk := &fakeClock{}
	ring, err := creds.NewKeyring([]byte("0123456789abcdef-interop"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{
		Realm:        realm,
		Auth:         ring.Auth(clk.Now),
		AuthExisting: ring.AuthExisting(),
		RelayIP:      netip.MustParseAddr("127.0.0.1"),
		AllowPeers:   []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		// The call must outlast the hour: the lifetimes and the nonce are widened
		// so that only the CREDENTIAL expires, as pion refreshes on real time.
		DefaultLifetime: 3 * time.Hour, MaxLifetime: 3 * time.Hour, NonceLifetime: 3 * time.Hour,
		Now: clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServePacketConn(pc)
	addr := pc.LocalAddr().String()

	username, password := ring.Mint("call", clk.Now().Add(time.Hour))
	c := pionWith(t, addr, username, password)
	relay, err := c.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	first, second := echoPeerAt(t), echoPeerAt(t)
	if !roundTrip(t, relay, first.LocalAddr(), []byte("before expiry")) {
		t.Fatal("no echo before expiry")
	}

	clk.Advance(61 * time.Minute)
	if _, ok := ring.Verify(username, clk.Now()); ok {
		t.Fatal("control: the credential should have expired")
	}
	// A NEW peer needs CreatePermission, then ChannelBind: both with the
	// expired username.
	if !roundTrip(t, relay, second.LocalAddr(), []byte("after expiry")) {
		t.Fatal("no echo through a permission created after the credential expired")
	}
	waitFor(t, "ChannelBind after expiry", func() bool { return srv.Stats().ChannelBinds >= 2 })

	// The same expired credential still cannot start an allocation.
	late := pionWith(t, addr, username, password)
	if r, err := late.Allocate(); err == nil {
		r.Close()
		t.Fatal("an expired credential allocated")
	}

	// Closing sends Refresh with LIFETIME 0, also under the expired username.
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "allocation deletion", func() bool { return srv.Stats().Allocations == 0 })
}
