package session

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-authn/oidc"
)

// ErrUnauthorized is the one refusal Subject gives, whatever the cause: a client
// that sent a bad token is not owed which check caught it.
var ErrUnauthorized = errors.New("session: unauthorized")

// Auth authenticates an API request from its Authorization: Bearer header: a
// turnd session token, or (when AccessTokens is set) an access token of the
// configured issuer, verified by go-authn/oidc.
type Auth struct {
	Signer *Signer
	// AccessTokens, when non-nil, accepts issuer access tokens. Build it with
	// oidc.Config{Type: "at+jwt"} so an ID token is never taken for one.
	AccessTokens *oidc.Verifier
	Now          func() time.Time
	// Logf receives the real reason for a refusal (never sent to the client).
	Logf func(ctx context.Context, format string, args ...any)
	// Observe receives the reason of every refusal as one fixed word:
	// "session_token" or "access_token" (a token that failed verification),
	// "no_access_verifier" (an issuer token with no verifier configured),
	// "no_subject". Nil observes nothing.
	Observe func(ctx context.Context, reason string)
}

// Bearer extracts the token of an Authorization: Bearer header.
func Bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || len(h) > MaxTokenLen+16 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	t := strings.TrimSpace(h[7:])
	return t, t != "" && !strings.ContainsAny(t, " \t")
}

// Subject returns the opaque subject of the request's bearer token.
func (a *Auth) Subject(r *http.Request) (string, error) {
	tok, ok := Bearer(r)
	if !ok {
		return "", ErrUnauthorized
	}
	return a.Authenticate(r.Context(), tok)
}

// Authenticate returns the opaque subject of a token: a turnd session token or
// an issuer access token. It is what a gRPC service calls with the token of
// its "authorization: Bearer" metadata.
func (a *Auth) Authenticate(ctx context.Context, tok string) (string, error) {
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	if isSessionToken(tok) {
		c, err := a.Signer.Verify(tok, now())
		if err != nil {
			a.logf(ctx, "session token refused: %v", err)
			a.observe(ctx, "session_token")
			return "", ErrUnauthorized
		}
		return c.Subject, nil
	}
	if a.AccessTokens == nil {
		a.observe(ctx, "no_access_verifier")
		return "", ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := a.AccessTokens.Verify(ctx, tok)
	if err != nil {
		a.logf(ctx, "access token refused: %v", err)
		a.observe(ctx, "access_token")
		return "", ErrUnauthorized
	}
	if t.Subject() == "" {
		a.observe(ctx, "no_subject")
		return "", ErrUnauthorized
	}
	return Subject(t.Issuer(), t.Subject()), nil
}

func (a *Auth) logf(ctx context.Context, f string, args ...any) {
	if a.Logf != nil {
		a.Logf(ctx, f, args...)
	}
}

func (a *Auth) observe(ctx context.Context, reason string) {
	if a.Observe != nil {
		a.Observe(ctx, reason)
	}
}
