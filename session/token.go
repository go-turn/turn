// Package session is turnd's own login: an OpenID Connect login through
// go-authn/rp in a popup window, and a short-lived bearer token turnd signs
// itself, which the playground then presents to the credential and rendezvous
// endpoints.
//
// The token is "t1.<payload>.<mac>" (both base64url): payload is the expiry
// (8 bytes, big endian Unix seconds), a 16-byte random nonce, then the subject;
// mac is HMAC-SHA256 over a domain-separation label and the payload, under a
// server key that never leaves turnd. It is compared in constant time and is
// refused when expired or altered.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// MinKeyLen is the shortest session key accepted (the HMAC-SHA256 output size).
	MinKeyLen = 32
	// MaxSubjectLen bounds the subject of a token.
	MaxSubjectLen = 128
	// MaxTokenLen bounds a token Verify reads; anything longer is refused unread.
	MaxTokenLen = 512

	prefix  = "t1." // v0.4.0 tokens: no family, cannot be renewed
	prefix2 = "t2." // payload adds a 16-byte renewal family before the subject
	label   = "go-turn/session v1\x00"
	label2  = "go-turn/session v2\x00"
	nonceN  = 16
	familyN = 16
)

// Family names the renewal family of a session: a random identifier under which
// turnd keeps the identity provider's refresh token server side. It is not a
// secret of its own (it only means something inside a token turnd signed).
type Family [familyN]byte

// IsZero says whether f is the absent family of a token that cannot be renewed.
func (f Family) IsZero() bool { return f == Family{} }

// isSessionToken says whether tok is one of ours, as opposed to an issuer
// access token.
func isSessionToken(tok string) bool {
	return strings.HasPrefix(tok, prefix) || strings.HasPrefix(tok, prefix2)
}

var (
	// ErrInvalid is a token that is malformed, signed by no key of ours, or altered.
	ErrInvalid = errors.New("session: invalid token")
	// ErrExpired is a genuine token whose time is over.
	ErrExpired = errors.New("session: token expired")
)

// Claims is what a verified token says.
type Claims struct {
	Subject string
	Expiry  time.Time
	Nonce   [nonceN]byte
	// Family is the renewal family; the zero value for a token that predates
	// renewal or was issued without one.
	Family Family
}

// Signer issues and verifies tokens. Issue signs with the first key; Verify
// accepts any of them, so a key can be rotated without logging everybody out.
type Signer struct {
	keys [][]byte
	ttl  time.Duration
}

// NewSigner is a signer with the given lifetime for tokens it issues. A key
// shorter than [MinKeyLen], a non-positive ttl or a duplicate key is refused.
func NewSigner(ttl time.Duration, current []byte, previous ...[]byte) (*Signer, error) {
	if ttl <= 0 {
		return nil, errors.New("session: ttl must be positive")
	}
	s := &Signer{ttl: ttl}
	for _, k := range append([][]byte{current}, previous...) {
		if len(k) < MinKeyLen {
			return nil, errors.New("session: a key is shorter than 32 bytes")
		}
		for _, have := range s.keys {
			if subtle.ConstantTimeCompare(have, k) == 1 {
				return nil, errors.New("session: two keys are the same")
			}
		}
		s.keys = append(s.keys, append([]byte(nil), k...))
	}
	return s, nil
}

// TTL is the lifetime of an issued token.
func (s *Signer) TTL() time.Duration { return s.ttl }

func mac(key, payload []byte) []byte { return macLabel(label, key, payload) }

func macLabel(l string, key, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(l))
	m.Write(payload)
	return m.Sum(nil)
}

// ValidSubject says whether s can be a token's subject: non-empty, UTF-8, at
// most [MaxSubjectLen] bytes, no control or space characters.
func ValidSubject(s string) bool {
	if s == "" || len(s) > MaxSubjectLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// Issue signs a token for subject, valid for the signer's ttl from now.
func (s *Signer) Issue(subject string, now time.Time) (token string, expiry time.Time, err error) {
	if !ValidSubject(subject) {
		return "", time.Time{}, errors.New("session: bad subject")
	}
	expiry = now.Add(s.ttl).Truncate(time.Second)
	payload := make([]byte, 8+nonceN, 8+nonceN+len(subject))
	binary.BigEndian.PutUint64(payload, uint64(expiry.Unix()))
	if _, err := rand.Read(payload[8:]); err != nil {
		return "", time.Time{}, err
	}
	payload = append(payload, subject...)
	enc := base64.RawURLEncoding
	return prefix + enc.EncodeToString(payload) + "." + enc.EncodeToString(mac(s.keys[0], payload)), expiry, nil
}

// IssueRenewable is [Signer.Issue] for a session that can be renewed: the token
// carries fam, which turnd's renewer maps to the stored refresh token.
func (s *Signer) IssueRenewable(subject string, fam Family, now time.Time) (token string, expiry time.Time, err error) {
	if !ValidSubject(subject) || fam.IsZero() {
		return "", time.Time{}, errors.New("session: bad subject or family")
	}
	expiry = now.Add(s.ttl).Truncate(time.Second)
	payload := make([]byte, 8+nonceN+familyN, 8+nonceN+familyN+len(subject))
	binary.BigEndian.PutUint64(payload, uint64(expiry.Unix()))
	if _, err := rand.Read(payload[8 : 8+nonceN]); err != nil {
		return "", time.Time{}, err
	}
	copy(payload[8+nonceN:], fam[:])
	payload = append(payload, subject...)
	enc := base64.RawURLEncoding
	return prefix2 + enc.EncodeToString(payload) + "." + enc.EncodeToString(macLabel(label2, s.keys[0], payload)), expiry, nil
}

// Verify checks a token. The signature is checked, against every key and in
// constant time, before anything in the payload is trusted; then the expiry.
func (s *Signer) Verify(token string, now time.Time) (Claims, error) {
	return s.VerifyGrace(token, now, 0)
}

// VerifyGrace is [Signer.Verify] that also accepts a genuine token expired for
// less than grace. It is for renewal only: every other endpoint uses Verify.
func (s *Signer) VerifyGrace(token string, now time.Time, grace time.Duration) (Claims, error) {
	if len(token) > MaxTokenLen {
		return Claims{}, ErrInvalid
	}
	var pre, lab string
	var fixed int
	switch {
	case strings.HasPrefix(token, prefix):
		pre, lab, fixed = prefix, label, 8+nonceN
	case strings.HasPrefix(token, prefix2):
		pre, lab, fixed = prefix2, label2, 8+nonceN+familyN
	default:
		return Claims{}, ErrInvalid
	}
	p, m, ok := strings.Cut(token[len(pre):], ".")
	if !ok {
		return Claims{}, ErrInvalid
	}
	enc := base64.RawURLEncoding
	payload, err1 := enc.DecodeString(p)
	sig, err2 := enc.DecodeString(m)
	if err1 != nil || err2 != nil || len(sig) != sha256.Size || len(payload) < fixed+1 {
		return Claims{}, ErrInvalid
	}
	good := 0
	for _, k := range s.keys {
		good |= subtle.ConstantTimeCompare(sig, macLabel(lab, k, payload))
	}
	if good != 1 {
		return Claims{}, ErrInvalid
	}
	// The payload is ours now; still re-validate what we parse.
	sec := binary.BigEndian.Uint64(payload)
	subject := string(payload[fixed:])
	if sec > uint64(1<<62) || !ValidSubject(subject) {
		return Claims{}, ErrInvalid
	}
	c := Claims{Subject: subject, Expiry: time.Unix(int64(sec), 0)}
	copy(c.Nonce[:], payload[8:8+nonceN])
	if pre == prefix2 {
		copy(c.Family[:], payload[8+nonceN:fixed])
	}
	if !c.Expiry.Add(grace).After(now) {
		return Claims{}, ErrExpired
	}
	return c, nil
}
