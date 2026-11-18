package server

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/go-turn/turn/stun"
)

type recorder struct {
	mu  sync.Mutex
	got []RequestInfo
}

func (r *recorder) Request(i RequestInfo) { r.mu.Lock(); r.got = append(r.got, i); r.mu.Unlock() }
func (r *recorder) all() []RequestInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RequestInfo(nil), r.got...)
}

func withObserver(r *recorder, more ...func(*Config)) func(*Config) {
	return func(c *Config) {
		c.Observer = r
		for _, m := range more {
			m(c)
		}
	}
}

func TestObserverSeesChallengeThenSuccessPerTransport(t *testing.T) {
	rec := &recorder{}
	e := start(t, true, withObserver(rec))
	for name, c := range map[string]*client{"udp": dialUDP(t, e.udp), "tcp": dialTCP(t, e.tcp), "tls": dialTLS(t, e.tls, e.cert)} {
		relayedOf(t, c.allocate(nil))
		var challenge, ok int
		for _, i := range rec.all() {
			if i.Transport != name || i.Method != "allocate" {
				continue
			}
			if !i.Received.IsZero() && i.End.Before(i.Received) {
				t.Fatalf("%s: End %v before Received %v", name, i.End, i.Received)
			}
			switch i.Code {
			case stun.CodeUnauthenticated:
				challenge++
			case 0:
				ok++
			}
		}
		if challenge != 1 || ok != 1 {
			t.Errorf("%s: want the RFC 8489 401 challenge then one success, got %d and %d: %+v", name, challenge, ok, rec.all())
		}
	}
}

func TestObserverNamesThePolicyClass(t *testing.T) {
	rec := &recorder{}
	e := start(t, false, withObserver(rec, ownCfg))
	c := dialUDP(t, e.udp)
	relayedOf(t, c.allocate(nil))
	want := map[string]string{
		"127.0.0.1:5000": "loopback", "10.0.0.1:1": "private", "192.168.1.1:1": "private", "172.16.0.1:1": "private",
		"100.64.0.1:1": "cgnat", "169.254.169.254:80": "metadata", "169.254.0.1:1": "link_local",
		"224.0.0.1:1": "multicast", "[::1]:1": "loopback", "[fe80::1]:1": "link_local", "[fc00::1]:1": "private",
		"[::ffff:127.0.0.1]:1": "loopback", "[::ffff:169.254.169.254]:80": "metadata",
		"[64:ff9b::7f00:1]:1": "translator", "[2002:7f00:1::]:1": "translator",
		"203.0.113.7:3478": "own_address", "203.0.113.9:0": "port_zero", "0.0.0.1:1": "reserved", "240.0.0.1:1": "reserved",
	}
	for p, class := range want {
		before := len(rec.all())
		if code := errCode(t, c.permit(netip.MustParseAddrPort(p))); code != stun.CodeForbidden {
			t.Fatalf("%s: %d", p, code)
		}
		got := rec.all()[before:]
		if len(got) != 1 || got[0].Method != "create_permission" || got[0].Code != 403 || got[0].Policy != class {
			t.Errorf("%s: want class %q, observer saw %+v", p, class, got)
		}
	}
	// a success carries no policy class
	before := len(rec.all())
	mustSuccess(t, c.permit(netip.MustParseAddrPort("198.51.100.1:1")))
	if got := rec.all()[before:]; len(got) != 1 || got[0].Policy != "" || got[0].Code != 0 {
		t.Errorf("success: %+v", got)
	}
}

func TestObserverNilIsFree(t *testing.T) {
	e := start(t, false, nil) // no Observer: Received must stay unset on the hot path
	c := dialUDP(t, e.udp)
	relayedOf(t, c.allocate(nil))
}

func TestStatsCountBytesAndUsageCountsPermissionsAndChannels(t *testing.T) {
	e := start(t, false, loopbackAllow)
	peer := echoPeer(t)
	c := dialUDP(t, e.udp)
	relayedOf(t, c.allocate(nil))
	mustSuccess(t, c.permit(peer))
	mustSuccess(t, c.bind(0x4001, peer))
	payload := []byte("0123456789")
	c.sendChan(0x4001, payload)
	if _, _, got, ok := c.data(2 * time.Second); !ok || string(got) != string(payload) {
		t.Fatalf("no echo: %q %v", got, ok)
	}
	st := e.srv.Stats()
	if st.BytesToPeer != uint64(len(payload)) || st.BytesToClient != uint64(len(payload)) || st.PacketsToPeer != 1 || st.PacketsToClient != 1 {
		t.Fatalf("stats %+v", st)
	}
	if u := e.srv.Usage(); u.Permissions != 1 || u.Channels != 1 {
		t.Fatalf("usage %+v", u)
	}
	e.clk.Advance(20 * time.Minute) // past the 5 min permission and 10 min channel lifetimes
	if u := e.srv.Usage(); u.Permissions != 0 || u.Channels != 0 {
		t.Fatalf("expired state still counted: %+v", u)
	}
}
