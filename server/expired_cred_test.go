package server

import (
	"testing"
	"time"

	turncreds "github.com/go-turn/turn/creds"
	"github.com/go-turn/turn/stun"
)

// A WebRTC call outlives the one-hour credential that opened it: Refresh,
// CreatePermission and ChannelBind of an EXISTING allocation must keep working
// with the username that created it, while the same expired username may not
// start a new allocation, nor touch another client's.

var (
	secretNew = []byte("0123456789abcdef-current")
	secretOld = []byte("fedcba9876543210-previous")
)

func ringOf(t *testing.T, current []byte, previous ...[]byte) *turncreds.Keyring {
	t.Helper()
	k, err := turncreds.NewKeyring(current, previous...)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// startRing serves with the keyring's expiry-checked Auth, and its
// expiry-free AuthExisting unless withExisting is false (the control).
func startRing(t *testing.T, ring *turncreds.Keyring, withExisting bool, mut func(*Config)) *env {
	t.Helper()
	return start(t, false, func(c *Config) {
		loopbackAllow(c)
		c.Auth = ring.Auth(c.Now)
		if withExisting {
			c.AuthExisting = ring.AuthExisting()
		}
		if mut != nil {
			mut(c)
		}
	})
}

func life(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 3600) }

func (c *client) refresh() *stun.Message { return c.authed(stun.MethodRefresh, life) }

func (e *env) mintFor(c *client, ring *turncreds.Keyring, subject string, ttl time.Duration) {
	c.user, c.pass = ring.Mint(subject, e.clk.Now().Add(ttl))
	c.nonce = ""
}

func TestExpiredUsernameKeepsItsOwnAllocation(t *testing.T) {
	ring := ringOf(t, secretNew)
	e := startRing(t, ring, true, nil)
	peer := echoPeer(t)
	c := dialUDP(t, e.udp)
	e.mintFor(c, ring, "call-1", time.Hour)
	relayedOf(t, c.allocate(nil))
	mustSuccess(t, c.refresh())
	mustSuccess(t, c.permit(peer))

	e.clk.Advance(55 * time.Minute) // still valid: the ordinary path
	mustSuccess(t, c.refresh())
	e.clk.Advance(10 * time.Minute) // 65 min: the username expired at 60

	if _, ok := ring.Verify(c.user, e.clk.Now()); ok {
		t.Fatal("control: the username should be expired by now")
	}
	mustSuccess(t, c.refresh())
	mustSuccess(t, c.permit(peer))
	mustSuccess(t, c.bind(0x4020, peer))

	// Data still flows, by indication and by channel.
	c.sendInd(peer, []byte("ping"))
	if _, _, d, ok := c.data(2 * time.Second); !ok || string(d) != "ping" {
		t.Fatalf("no relayed data after expiry: %q %v", d, ok)
	}
	c.sendChan(0x4020, []byte("chan"))
	if _, ch, d, ok := c.data(2 * time.Second); !ok || ch != 0x4020 || string(d) != "chan" {
		t.Fatalf("no channel data after expiry: %x %q %v", ch, d, ok)
	}
}

func TestExpiredUsernameWithoutHookEndsItsAllocation(t *testing.T) {
	// Control: the behaviour of v0.4.0, which the hook exists to change.
	ring := ringOf(t, secretNew)
	e := startRing(t, ring, false, nil)
	c := dialUDP(t, e.udp)
	e.mintFor(c, ring, "call-1", time.Hour)
	relayedOf(t, c.allocate(nil))
	mustSuccess(t, c.refresh())
	e.clk.Advance(30 * time.Minute)
	mustSuccess(t, c.refresh())
	e.clk.Advance(31 * time.Minute)
	if got := errCode(t, c.refresh()); got != 401 {
		t.Fatalf("expired username without AuthExisting: %d, want 401", got)
	}
}

func TestExpiredUsernameCannotAllocate(t *testing.T) {
	ring := ringOf(t, secretNew)
	e := startRing(t, ring, true, nil)
	c := dialUDP(t, e.udp)
	e.mintFor(c, ring, "late", time.Hour)
	e.clk.Advance(61 * time.Minute)
	if got := errCode(t, c.allocate(nil)); got != 401 {
		t.Fatalf("Allocate with an expired username: %d, want 401", got)
	}
	if n := e.srv.Stats().Allocations; n != 0 {
		t.Fatalf("%d allocations exist", n)
	}
	// Control: a fresh username from the same ring allocates.
	e.mintFor(c, ring, "late", time.Hour)
	relayedOf(t, c.allocate(nil))
}

func TestExpiredUsernameRefusedOnAnotherClientsAllocation(t *testing.T) {
	ring := ringOf(t, secretNew)
	e := startRing(t, ring, true, nil)
	peer := echoPeer(t)
	a := dialUDP(t, e.udp)
	e.mintFor(a, ring, "alice", time.Hour)
	relayedOf(t, a.allocate(nil))
	mustSuccess(t, a.refresh())
	expired := a.user

	b := dialUDP(t, e.udp) // another 5-tuple, holding A's (soon expired) username
	e.mintFor(b, ring, "alice", time.Hour)
	b.user, b.pass = a.user, a.pass
	e.clk.Advance(61 * time.Minute)
	for name, r := range map[string]*stun.Message{
		"refresh": b.refresh(), "permission": b.permit(peer), "bind": b.bind(0x4030, peer),
	} {
		if got := errCode(t, r); got != 401 {
			t.Errorf("%s of another client with an expired username: %d, want 401", name, got)
		}
	}
	// The owner is untouched.
	if a.user != expired {
		t.Fatal("test bug")
	}
	mustSuccess(t, a.refresh())
}

func TestOtherUsernameOnExistingAllocationRefused(t *testing.T) {
	ring := ringOf(t, secretNew)
	e := startRing(t, ring, true, nil)
	c := dialUDP(t, e.udp)
	e.mintFor(c, ring, "alice", time.Hour)
	relayedOf(t, c.allocate(nil))
	oldUser, oldPass := c.user, c.pass

	// Same socket, another subject, still valid: 441 as before.
	e.mintFor(c, ring, "mallory", time.Hour)
	if got := errCode(t, c.refresh()); got != 441 {
		t.Fatalf("valid username of another subject: %d, want 441", got)
	}
	// Same socket, another subject, EXPIRED: the expiry exemption is not theirs.
	user2, pass2 := ring.Mint("mallory", e.clk.Now().Add(time.Minute))
	e.clk.Advance(2 * time.Minute)
	c.user, c.pass, c.nonce = user2, pass2, ""
	if got := errCode(t, c.refresh()); got != 401 {
		t.Fatalf("expired username of another subject: %d, want 401", got)
	}
	// The owner's own request is accepted (its username is still valid here).
	c.user, c.pass, c.nonce = oldUser, oldPass, ""
	mustSuccess(t, c.refresh())
}

func TestExpiredUsernameWithWrongPasswordRefused(t *testing.T) {
	// The exemption waives the expiry only: MESSAGE-INTEGRITY still decides.
	ring := ringOf(t, secretNew)
	e := startRing(t, ring, true, nil)
	c := dialUDP(t, e.udp)
	e.mintFor(c, ring, "call", time.Hour)
	relayedOf(t, c.allocate(nil))
	e.clk.Advance(61 * time.Minute)
	c.pass = "not-the-password"
	if got := errCode(t, c.refresh()); got != 401 {
		t.Fatalf("expired username, wrong password: %d, want 401", got)
	}
}

func TestMaxAllocationAge(t *testing.T) {
	t.Run("expired username refused past the bound", func(t *testing.T) {
		ring := ringOf(t, secretNew)
		e := startRing(t, ring, true, func(c *Config) { c.MaxAllocationAge = 2 * time.Hour })
		c := dialUDP(t, e.udp)
		e.mintFor(c, ring, "call", time.Hour)
		relayedOf(t, c.allocate(nil))
		for i := 0; i < 5; i++ { // 5 x 20 min: 100 min, expired since 60
			e.clk.Advance(20 * time.Minute)
			mustSuccess(t, c.refresh())
		}
		e.clk.Advance(21 * time.Minute) // 121 min
		if got := errCode(t, c.refresh()); got != 401 {
			t.Fatalf("refresh past MaxAllocationAge with an expired username: %d, want 401", got)
		}
	})
	t.Run("valid username refused past the bound", func(t *testing.T) {
		ring := ringOf(t, secretNew)
		e := startRing(t, ring, true, func(c *Config) { c.MaxAllocationAge = 90 * time.Minute })
		c := dialUDP(t, e.udp)
		e.mintFor(c, ring, "call", 10*time.Hour)
		relayedOf(t, c.allocate(nil))
		for i := 0; i < 4; i++ {
			e.clk.Advance(20 * time.Minute)
			mustSuccess(t, c.refresh())
		}
		e.clk.Advance(11 * time.Minute) // 91 min
		if got := errCode(t, c.refresh()); got != 403 {
			t.Fatalf("refresh past MaxAllocationAge: %d, want 403", got)
		}
		// Deleting stays possible.
		mustSuccess(t, c.authed(stun.MethodRefresh, func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 0) }))
	})
	t.Run("default is twelve hours", func(t *testing.T) {
		e := startRing(t, ringOf(t, secretNew), true, nil)
		if got := e.srv.cfg.MaxAllocationAge; got != 12*time.Hour {
			t.Fatalf("default %v", got)
		}
	})
}

func TestExpiredUsernameAcrossSecretRotation(t *testing.T) {
	oldRing := ringOf(t, secretOld)
	// The server rotated: signs with secretNew, still honours secretOld.
	ring := ringOf(t, secretNew, secretOld)
	e := startRing(t, ring, true, nil)
	c := dialUDP(t, e.udp)
	e.mintFor(c, oldRing, "call", time.Hour) // minted before the rotation
	relayedOf(t, c.allocate(nil))
	e.clk.Advance(30 * time.Minute)
	mustSuccess(t, c.refresh())
	e.clk.Advance(31 * time.Minute)
	mustSuccess(t, c.refresh()) // expired, and the old secret still verifies

	// Control: a ring that has DROPPED the old secret derives nothing for it.
	gone := ringOf(t, secretNew)
	if _, ok := gone.Password(c.user); ok {
		t.Fatal("a username of a dropped secret got a password")
	}
	e2 := startRing(t, gone, true, nil)
	c2 := dialUDP(t, e2.udp)
	e2.mintFor(c2, ring, "call", time.Hour) // signed by the current secret of the first ring: valid here
	relayedOf(t, c2.allocate(nil))
	e2.mintFor(c2, oldRing, "x", time.Hour)
	if got := errCode(t, c2.refresh()); got != 401 {
		t.Fatalf("username of a dropped secret: %d, want 401", got)
	}
}
