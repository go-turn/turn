// Package creds mints and checks ephemeral TURN credentials, the scheme of
// draft-uberti-behave-turn-rest-00 (J. Uberti, "A REST API For Access To TURN
// Services", July 2013).
//
// The web service and the TURN server share only a secret. The username
// encodes all the state, "<unix-expiry>:<subject>" (§2.2), and the password is
// base64(HMAC-SHA1(secret, username)) (§2.2). The TURN server splits the
// USERNAME, refuses it once the timestamp has passed (§4.2), and uses the same
// derivation as the long-term-credential password, so a good MESSAGE-INTEGRITY
// proves the username, and the expiry inside it, is ours (§4.2).
//
// The subject should be opaque (§6): a username is visible to eavesdroppers.
//
// A [Keyring] adds the rotation of §5.2 (more than one secret valid at a time).
// The draft leaves open how a server that holds a single password per username
// learns WHICH secret signed it, so a Keyring prefixes the subject with a
// four-hex-digit key tag (a one-way hash of the secret, never the secret).
package creds

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is the scheme of the draft and of TURN's MESSAGE-INTEGRITY.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxUsernameLen bounds a username Verify accepts. A STUN USERNAME attribute is
// at most 513 bytes (RFC 8489 §14.3); this is far below it.
const MaxUsernameLen = 256

// MaxExpiry is the latest expiry (Unix seconds) Parse accepts: 9999-12-31. A
// larger value overflows time.Time, whose comparisons then lie.
const MaxExpiry = 253402300799

// MinSecretLen is the shortest secret a [Keyring] accepts (an HMAC key shorter
// than its hash output is weaker than the hash).
const MinSecretLen = 16

// Mint returns the credentials for subject, valid until expiry:
// username "<unix-expiry>:<subject>" and password base64(HMAC-SHA1(secret,
// username)). Whole seconds: the expiry is truncated to its Unix second.
func Mint(secret []byte, subject string, expiry time.Time) (username, password string) {
	username = strconv.FormatInt(expiry.Unix(), 10) + ":" + subject
	return username, password1(secret, username)
}

func password1(secret []byte, username string) string {
	m := hmac.New(sha1.New, secret)
	m.Write([]byte(username))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Parse splits a username into its expiry and subject. It refuses a username
// that is overlong, not "<digits>:<subject>", whose expiry has a sign, a
// leading zero or overflows, or whose subject is empty, not UTF-8 or holds a
// control or space character.
func Parse(username string) (expiry time.Time, subject string, ok bool) {
	if len(username) > MaxUsernameLen {
		return time.Time{}, "", false
	}
	ts, subject, found := strings.Cut(username, ":")
	if !found || subject == "" || ts == "" || len(ts) > 12 {
		return time.Time{}, "", false
	}
	for i := 0; i < len(ts); i++ {
		if ts[i] < '0' || ts[i] > '9' {
			return time.Time{}, "", false
		}
	}
	if len(ts) > 1 && ts[0] == '0' {
		return time.Time{}, "", false
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sec > MaxExpiry {
		return time.Time{}, "", false
	}
	if !utf8.ValidString(subject) {
		return time.Time{}, "", false
	}
	for _, r := range subject {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == utf8.RuneError {
			return time.Time{}, "", false
		}
	}
	return time.Unix(sec, 0), subject, true
}

// Verify checks username against now and returns the password the client must
// have derived: the TURN server's long-term-credential lookup. It refuses an
// expired username (expiry <= now, §4.2), a malformed or overlong one.
func Verify(secret []byte, username string, now time.Time) (password string, ok bool) {
	exp, _, ok := Parse(username)
	if !ok || !exp.After(now) {
		return "", false
	}
	return password1(secret, username), true
}

// Keyring is a current secret followed by the previous ones still honoured
// (§5.2). Mint signs with the current one; Verify finds the one the username
// names. The zero value is unusable: build one with [NewKeyring].
type Keyring struct {
	secrets [][]byte
	tags    []string
}

// NewKeyring is a keyring signing with current and accepting previous. A secret
// shorter than [MinSecretLen] or a duplicate is refused.
func NewKeyring(current []byte, previous ...[]byte) (*Keyring, error) {
	k := &Keyring{}
	for _, s := range append([][]byte{current}, previous...) {
		if len(s) < MinSecretLen {
			return nil, errShort
		}
		t := tag(s)
		for _, have := range k.tags {
			if have == t {
				return nil, errDuplicate
			}
		}
		k.secrets = append(k.secrets, append([]byte(nil), s...))
		k.tags = append(k.tags, t)
	}
	return k, nil
}

type keyringError string

func (e keyringError) Error() string { return string(e) }

const (
	errShort     keyringError = "creds: a secret is shorter than 16 bytes"
	errDuplicate keyringError = "creds: two secrets are the same"
)

// tag is a public, one-way name for a secret: 16 bits of a domain-separated
// SHA-256. It tells which key to try, it grants nothing.
func tag(secret []byte) string {
	h := sha256.Sum256(append([]byte("go-turn/creds key tag\x00"), secret...))
	return hex.EncodeToString(h[:2])
}

// Mint is [Mint] with the current secret; the username's subject part is
// "<tag>.<subject>".
func (k *Keyring) Mint(subject string, expiry time.Time) (username, password string) {
	return Mint(k.secrets[0], k.tags[0]+"."+subject, expiry)
}

// Verify is [Verify] with the secret the username's tag names. A username that
// names no key of the ring is refused.
func (k *Keyring) Verify(username string, now time.Time) (password string, ok bool) {
	_, subject, ok := Parse(username)
	if !ok || len(subject) < 6 || subject[4] != '.' {
		return "", false
	}
	for i, t := range k.tags {
		if t == subject[:4] {
			return Verify(k.secrets[i], username, now)
		}
	}
	return "", false
}

// Password derives the password of a well-formed username whose key tag names a
// secret of the ring, WITHOUT checking the expiry. It is for a request on an
// allocation that already exists: the HMAC in MESSAGE-INTEGRITY still proves
// the username is ours, the expiry only governs who may START one. Callers
// bound the extra life themselves (server.Config.MaxAllocationAge).
func (k *Keyring) Password(username string) (password string, ok bool) {
	_, subject, ok := Parse(username)
	if !ok || len(subject) < 6 || subject[4] != '.' {
		return "", false
	}
	for i, t := range k.tags {
		if t == subject[:4] {
			return password1(k.secrets[i], username), true
		}
	}
	return "", false
}

// AuthExisting is [Keyring.Password] as the hook of server.Config.AuthExisting.
func (k *Keyring) AuthExisting() func(username string) (string, bool) {
	return k.Password
}

// Auth is the TURN server's credential hook, func(username) (password, ok),
// reading the clock from now (time.Now when nil).
func (k *Keyring) Auth(now func() time.Time) func(username string) (string, bool) {
	if now == nil {
		now = time.Now
	}
	return func(u string) (string, bool) { return k.Verify(u, now()) }
}
