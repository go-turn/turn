package session

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

var (
	t0   = time.Unix(1_800_000_000, 0)
	key1 = []byte("0123456789abcdef0123456789abcdef")
	key2 = []byte("fedcba9876543210fedcba9876543210")
)

func signer(t *testing.T, keys ...[]byte) *Signer {
	t.Helper()
	s, err := NewSigner(10*time.Minute, keys[0], keys[1:]...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRoundTrip(t *testing.T) {
	s := signer(t, key1)
	tok, exp, err := s.Issue("alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(t0.Add(10 * time.Minute)) {
		t.Fatalf("expiry %v", exp)
	}
	c, err := s.Verify(tok, t0.Add(time.Minute))
	if err != nil || c.Subject != "alice" || !c.Expiry.Equal(exp) {
		t.Fatalf("%+v %v", c, err)
	}
	tok2, _, _ := s.Issue("alice", t0)
	if tok == tok2 {
		t.Fatal("two tokens for the same subject and time are identical: the nonce is missing")
	}
}

func TestRefusals(t *testing.T) {
	s := signer(t, key1)
	tok, exp, _ := s.Issue("alice", t0)
	if _, err := s.Verify(tok, exp); err != ErrExpired {
		t.Fatalf("at expiry: %v", err)
	}
	if _, err := s.Verify(tok, exp.Add(time.Hour)); err != ErrExpired {
		t.Fatalf("after expiry: %v", err)
	}
	// control: the same token one second before expiry is good.
	if _, err := s.Verify(tok, exp.Add(-time.Second)); err != nil {
		t.Fatalf("control: %v", err)
	}
	p, m, _ := strings.Cut(strings.TrimPrefix(tok, "t1."), ".")
	raw, _ := base64.RawURLEncoding.DecodeString(p)
	flip := func(i int) string {
		b := append([]byte(nil), raw...)
		b[i] ^= 1
		return "t1." + base64.RawURLEncoding.EncodeToString(b) + "." + m
	}
	for name, bad := range map[string]string{
		"expiry bit":  flip(7),
		"nonce bit":   flip(10),
		"subject bit": flip(len(raw) - 1),
		"truncated":   tok[:len(tok)-2],
		"no prefix":   strings.TrimPrefix(tok, "t1."),
		"other mac":   "t1." + p + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"no dot":      "t1." + p,
		"empty":       "",
		"huge":        "t1." + strings.Repeat("A", MaxTokenLen),
		"bad base64":  "t1.!!!.!!!",
	} {
		if _, err := s.Verify(bad, t0); err != ErrInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := signer(t, key2).Verify(tok, t0); err != ErrInvalid {
		t.Errorf("another server's key: %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	old := signer(t, key1)
	tok, _, _ := old.Issue("alice", t0)
	rot := signer(t, key2, key1)
	if _, err := rot.Verify(tok, t0); err != nil {
		t.Fatalf("previous key: %v", err)
	}
	nt, _, _ := rot.Issue("bob", t0)
	if _, err := old.Verify(nt, t0); err != ErrInvalid {
		t.Fatalf("old signer accepted a new key: %v", err)
	}
	if _, err := signer(t, key2).Verify(tok, t0); err != ErrInvalid {
		t.Fatalf("dropped key still verifies: %v", err)
	}
}

func TestConfigRefusals(t *testing.T) {
	if _, err := NewSigner(0, key1); err == nil {
		t.Error("zero ttl")
	}
	if _, err := NewSigner(time.Minute, []byte("short")); err == nil {
		t.Error("short key")
	}
	if _, err := NewSigner(time.Minute, key1, key1); err == nil {
		t.Error("duplicate key")
	}
	s := signer(t, key1)
	for _, bad := range []string{"", "a b", "a\nb", strings.Repeat("a", MaxSubjectLen+1), "a\xffb"} {
		if _, _, err := s.Issue(bad, t0); err == nil {
			t.Errorf("subject %q accepted", bad)
		}
	}
	if _, _, err := s.Issue(strings.Repeat("a", MaxSubjectLen), t0); err != nil {
		t.Errorf("max subject: %v", err)
	}
}

func FuzzVerify(f *testing.F) {
	s, _ := NewSigner(time.Minute, key1)
	tok, _, _ := s.Issue("alice", t0)
	f.Add(tok)
	f.Add("t1..")
	f.Fuzz(func(t *testing.T, tok string) {
		c, err := s.Verify(tok, t0)
		if err == nil && (!ValidSubject(c.Subject) || !c.Expiry.After(t0)) {
			t.Fatalf("accepted %q as %+v", tok, c)
		}
	})
}
