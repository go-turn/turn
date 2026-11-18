package creds

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // the scheme's own algorithm.
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

var t0 = time.Unix(1_800_000_000, 0)

// Password derives what Verify would, minus the expiry check, and refuses the
// same malformed or unknown-key usernames.
func TestKeyringPasswordIgnoresExpiryOnly(t *testing.T) {
	cur, old := []byte("0123456789abcdef-current"), []byte("fedcba9876543210-previous")
	ring, err := NewKeyring(cur, old)
	if err != nil {
		t.Fatal(err)
	}
	oldOnly, _ := NewKeyring(old)
	other, _ := NewKeyring([]byte("zzzzzzzzzzzzzzzz-unknown"))
	exp := t0.Add(time.Hour)
	for name, tc := range map[string]struct {
		mint *Keyring
		want bool
	}{
		"current secret": {ring, true}, "previous secret": {oldOnly, true}, "unknown secret": {other, false},
	} {
		user, pass := tc.mint.Mint("s", exp)
		if _, ok := ring.Verify(user, t0.Add(2*time.Hour)); ok {
			t.Fatalf("%s: control, Verify accepted an expired username", name)
		}
		got, ok := ring.Password(user)
		if ok != tc.want || (ok && got != pass) {
			t.Errorf("%s: Password = %q, %v; want %q, %v", name, got, ok, pass, tc.want)
		}
		if fn, ok2 := ring.AuthExisting()(user); ok2 != tc.want || fn != got {
			t.Errorf("%s: AuthExisting disagrees with Password", name)
		}
	}
	for _, bad := range []string{"", "x", "abc:abcd.s", "01:abcd.s", "123:", "123:abc", strings.Repeat("1", 13) + ":abcd.s"} {
		if _, ok := ring.Password(bad); ok {
			t.Errorf("Password accepted %q", bad)
		}
	}
}

// RFC 2202 §3 test case 2 pins the HMAC-SHA1 primitive.
func TestHMACKnownAnswer(t *testing.T) {
	m := hmac.New(sha1.New, []byte("Jefe"))
	m.Write([]byte("what do ya want for nothing?"))
	if got := hex.EncodeToString(m.Sum(nil)); got != "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" {
		t.Fatalf("oracle: %s", got)
	}
	want := base64.StdEncoding.EncodeToString(m.Sum(nil))
	if got := password1([]byte("Jefe"), "what do ya want for nothing?"); got != want {
		t.Fatalf("password1 = %s, want %s", got, want)
	}
}

func TestMintShape(t *testing.T) {
	u, p := Mint([]byte("secret"), "mbzrxpgjys", t0.Add(time.Hour))
	if u != "1800003600:mbzrxpgjys" {
		t.Fatalf("username %q", u)
	}
	raw, err := base64.StdEncoding.DecodeString(p)
	if err != nil || len(raw) != sha1.Size {
		t.Fatalf("password %q: %v", p, err)
	}
	got, ok := Verify([]byte("secret"), u, t0)
	if !ok || got != p {
		t.Fatalf("verify: %q %v", got, ok)
	}
	if _, ok := Verify([]byte("other-secret"), u, t0); !ok {
		t.Fatal("Verify returns the password for ITS secret; a client holding another one fails at MESSAGE-INTEGRITY")
	}
	if g, _ := Verify([]byte("other-secret"), u, t0); g == p {
		t.Fatal("another secret gave the same password")
	}
}

func TestVerifyRefuses(t *testing.T) {
	s := []byte("0123456789abcdef")
	exp := strconv.FormatInt(t0.Unix()+60, 10)
	for _, c := range []struct {
		name, user string
		now        time.Time
	}{
		{"expired", strconv.FormatInt(t0.Unix()-1, 10) + ":alice", t0},
		{"expires exactly now", strconv.FormatInt(t0.Unix(), 10) + ":alice", t0},
		{"no colon", exp, t0},
		{"empty subject", exp + ":", t0},
		{"empty expiry", ":alice", t0},
		{"signed expiry", "+" + exp + ":alice", t0},
		{"negative expiry", "-5:alice", t0},
		{"leading zero", "0" + exp + ":alice", t0},
		{"hex expiry", "0x10:alice", t0},
		{"overflow", "99999999999999999999:alice", t0},
		{"max int64", "9223372036854775807:alice", t0},
		{"year 10000", "253402300800:alice", t0},
		{"space in subject", exp + ":al ice", t0},
		{"newline in subject", exp + ":al\nice", t0},
		{"NUL in subject", exp + ":al\x00ice", t0},
		{"invalid utf8", exp + ":al\xffice", t0},
		{"overlong", exp + ":" + strings.Repeat("a", MaxUsernameLen), t0},
		{"empty", "", t0},
	} {
		if p, ok := Verify(s, c.user, c.now); ok || p != "" {
			t.Errorf("%s: accepted %q", c.name, c.user)
		}
	}
	// control: the same shapes with the one fault removed are accepted.
	for _, user := range []string{exp + ":alice", exp + ":a:b", "253402300799:alice",
		exp + ":" + strings.Repeat("a", MaxUsernameLen-len(exp)-1)} {
		if _, ok := Verify(s, user, t0); !ok {
			t.Errorf("control refused %q", user)
		}
	}
}

func TestKeyringRotation(t *testing.T) {
	old := []byte("old-secret-0123456789")
	cur := []byte("new-secret-0123456789")
	oldRing, err := NewKeyring(old)
	if err != nil {
		t.Fatal(err)
	}
	oldUser, oldPass := oldRing.Mint("alice", t0.Add(time.Hour))
	ring, err := NewKeyring(cur, old)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := ring.Verify(oldUser, t0); !ok || p != oldPass {
		t.Fatalf("a username signed by a previous secret must still verify: %q %v", p, ok)
	}
	newUser, newPass := ring.Mint("alice", t0.Add(time.Hour))
	if newUser == oldUser {
		t.Fatal("two keys, one username")
	}
	if p, ok := ring.Verify(newUser, t0); !ok || p != newPass {
		t.Fatalf("current: %q %v", p, ok)
	}
	// the retired ring no longer knows the new key; a ring without the old key refuses the old user.
	if _, ok := oldRing.Verify(newUser, t0); ok {
		t.Fatal("the old ring accepted a username of a key it does not hold")
	}
	only, _ := NewKeyring(cur)
	if _, ok := only.Verify(oldUser, t0); ok {
		t.Fatal("a dropped secret still verifies")
	}
	if _, ok := ring.Verify(newUser, t0.Add(2*time.Hour)); ok {
		t.Fatal("expired accepted")
	}
	for _, bad := range []string{"1800003600:alice", "1800003600:zzzz.alice", "1800003600:abc", "1800003600:abcd."} {
		if _, ok := ring.Verify(bad, t0); ok {
			t.Errorf("untagged/unknown tag accepted: %q", bad)
		}
	}
	if auth := ring.Auth(func() time.Time { return t0 }); func() bool { _, ok := auth(newUser); return ok }() == false {
		t.Fatal("Auth hook refused a good username")
	}
}

func TestKeyringRefuses(t *testing.T) {
	if _, err := NewKeyring([]byte("short")); err == nil {
		t.Error("short secret accepted")
	}
	good := []byte("0123456789abcdef")
	if _, err := NewKeyring(good, good); err == nil {
		t.Error("duplicate accepted")
	}
	if _, err := NewKeyring(good, []byte("x")); err == nil {
		t.Error("short previous accepted")
	}
}

func TestResponseShape(t *testing.T) {
	r := NewResponse([]string{"stun:t.example:3478"}, []string{"turn:t.example:3478?transport=udp"},
		"1:u", "pw", t0.Add(90*time.Second), t0)
	b, _ := json.Marshal(r)
	want := `{"iceServers":[{"urls":["stun:t.example:3478"]},{"urls":["turn:t.example:3478?transport=udp"],"username":"1:u","credential":"pw"}],"ttl":90}`
	if string(b) != want {
		t.Fatalf("%s", b)
	}
	if r := NewResponse(nil, nil, "", "", t0.Add(-time.Hour), t0); r.TTL != 0 || r.ICEServers == nil {
		t.Fatalf("empty/negative: %+v", r)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"1800003600:alice", "", ":", "0:x", "1:a b", "9223372036854775807:z",
		"18446744073709551616:z", "-1:z", "1800003600:\x00", "1800003600:é", strings.Repeat("9", 300)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, u string) {
		exp, subj, ok := Parse(u)
		secret := []byte("0123456789abcdef")
		pw, vok := Verify(secret, u, time.Unix(0, 0))
		if !ok {
			if vok || pw != "" {
				t.Fatalf("Verify accepted what Parse refused: %q", u)
			}
			return
		}
		if len(u) > MaxUsernameLen || subj == "" {
			t.Fatalf("accepted %q", u)
		}
		if got := strconv.FormatInt(exp.Unix(), 10) + ":" + subj; got != u {
			t.Fatalf("not canonical: %q reformats to %q", u, got)
		}
		if exp.Unix() > 0 && !vok {
			t.Fatalf("future username refused: %q", u)
		}
		if _, e := Verify(secret, u, exp); e {
			t.Fatalf("expiry instant accepted: %q", u)
		}
		// Mint then Parse round-trips.
		mu, _ := Mint(secret, subj, exp)
		if mu != u {
			t.Fatalf("Mint(%q) = %q, want %q", subj, mu, u)
		}
	})
}

func FuzzKeyringVerify(f *testing.F) {
	ring, _ := NewKeyring([]byte("0123456789abcdef"), []byte("fedcba9876543210"))
	u, _ := ring.Mint("alice", time.Unix(4_000_000_000, 0))
	f.Add(u)
	f.Add("4000000000:abcd.alice")
	f.Fuzz(func(t *testing.T, u string) {
		if p, ok := ring.Verify(u, time.Unix(0, 0)); ok {
			if _, _, pok := Parse(u); !pok || p == "" {
				t.Fatalf("accepted %q", u)
			}
		}
	})
}
