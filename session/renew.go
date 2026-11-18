package session

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-authn/rp"
)

// ErrEnded is the one refusal [Renewer.Renew] gives for a session that cannot be
// renewed, whatever the cause: the person must sign in again.
var ErrEnded = errors.New("session: cannot be renewed, sign in again")

// ErrUnavailable is a renewal that could not be tried or finished because the
// identity provider did not answer. The session is intact: retry.
var ErrUnavailable = errors.New("session: the identity provider did not answer, retry")

// Refresher is the part of go-authn/rp's *rp.Client a renewal needs.
type Refresher interface {
	Refresh(ctx context.Context, refreshToken string, f rp.For) (*rp.Token, error)
}

// RenewConfig configures [NewRenewer].
type RenewConfig struct {
	Refresher Refresher
	Signer    *Signer
	// Lifetime is how long a family lives from the login: the identity
	// provider's refresh lifetime (bridge: the client's refresh_lifetime, fixed
	// at the login, not extended by rotation). Default 168 h.
	Lifetime time.Duration
	// Grace is how long after its expiry a session token can still be renewed
	// (default 5 minutes).
	Grace time.Duration
	// MaxFamilies bounds the store (default 10000). When it is full the family
	// closest to its end is dropped to make room: its person signs in again.
	MaxFamilies int
	Now         func() time.Time
	// Logf receives one line per outcome: the pseudonymous subject, never a
	// token or a family identifier.
	Logf func(format string, args ...any)
}

// Renewer keeps refresh tokens server side, in memory, keyed by family, and
// renews session tokens with them. A restart empties it: everybody signs in
// again.
type Renewer struct {
	cfg RenewConfig

	mu   sync.Mutex
	fams map[Family]*family
}

type family struct {
	subject  string
	refresh  string
	until    time.Time
	inflight *call
}

// call is a renewal in progress; concurrent renewals of one family wait for it
// and share its answer, so a refresh token is never spent twice.
type call struct {
	done  chan struct{}
	token string
	exp   time.Time
	err   error
}

// NewRenewer validates cfg.
func NewRenewer(cfg RenewConfig) (*Renewer, error) {
	if cfg.Refresher == nil || cfg.Signer == nil {
		return nil, errors.New("session: a renewer needs a refresher and a signer")
	}
	if cfg.Lifetime <= 0 {
		cfg.Lifetime = 168 * time.Hour
	}
	if cfg.Grace <= 0 {
		cfg.Grace = 5 * time.Minute
	}
	if cfg.MaxFamilies <= 0 {
		cfg.MaxFamilies = 10000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Renewer{cfg: cfg, fams: map[Family]*family{}}, nil
}

// Families is the number of families held.
func (r *Renewer) Families() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.fams)
}

func (r *Renewer) sweepLocked(now time.Time) {
	for k, f := range r.fams {
		if !f.until.After(now) {
			delete(r.fams, k)
		}
	}
}

// Open starts a family for a login that came with a refresh token and returns
// its identifier, to embed in the session token (Signer.IssueRenewable).
func (r *Renewer) Open(subject, refreshToken string) (Family, error) {
	if refreshToken == "" || !ValidSubject(subject) {
		return Family{}, errors.New("session: no refresh token or bad subject")
	}
	var fam Family
	if _, err := rand.Read(fam[:]); err != nil {
		return Family{}, err
	}
	now := r.cfg.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)
	if len(r.fams) >= r.cfg.MaxFamilies {
		var oldest Family
		var end time.Time
		for k, f := range r.fams {
			if end.IsZero() || f.until.Before(end) {
				oldest, end = k, f.until
			}
		}
		delete(r.fams, oldest)
		r.cfg.Logf("renewal store full: dropped the family closest to its end")
	}
	r.fams[fam] = &family{subject: subject, refresh: refreshToken, until: now.Add(r.cfg.Lifetime)}
	return fam, nil
}

// Renew trades a session token, valid or expired for less than the grace, for a
// new one. Any refusal from the provider ends the family ([ErrEnded]); a failure
// to reach it leaves it ([ErrUnavailable]).
func (r *Renewer) Renew(ctx context.Context, token string) (string, time.Time, error) {
	now := r.cfg.Now()
	c, err := r.cfg.Signer.VerifyGrace(token, now, r.cfg.Grace)
	if err != nil {
		r.cfg.Logf("renewal refused: %v", err)
		return "", time.Time{}, ErrEnded
	}
	if c.Family.IsZero() {
		r.cfg.Logf("renewal refused for %s: the token predates renewal", c.Subject)
		return "", time.Time{}, ErrEnded
	}
	r.mu.Lock()
	f, ok := r.fams[c.Family]
	if !ok || f.subject != c.Subject || !f.until.After(now) {
		delete(r.fams, c.Family)
		r.mu.Unlock()
		r.cfg.Logf("renewal refused for %s: no live family (lost at a restart, or its lifetime is over)", c.Subject)
		return "", time.Time{}, ErrEnded
	}
	if cl := f.inflight; cl != nil {
		r.mu.Unlock()
		select {
		case <-cl.done:
			return cl.token, cl.exp, cl.err
		case <-ctx.Done():
			return "", time.Time{}, fmt.Errorf("%w: %v", ErrUnavailable, ctx.Err())
		}
	}
	cl := &call{done: make(chan struct{})}
	f.inflight = cl
	rt := f.refresh
	r.mu.Unlock()

	// The refresh token may be spent by this call even if the client gives up,
	// and the rotated one must then be stored: the provider call is not tied
	// to the caller's context.
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	tok, rerr := r.cfg.Refresher.Refresh(pctx, rt, rp.For{})
	cancel()

	r.mu.Lock()
	f.inflight = nil
	switch {
	case rerr == nil:
		if tok != nil && tok.RefreshToken != "" {
			f.refresh = tok.RefreshToken
		}
		cl.token, cl.exp, cl.err = r.cfg.Signer.IssueRenewable(c.Subject, c.Family, r.cfg.Now())
		if cl.err != nil {
			cl.err = fmt.Errorf("%w: %v", ErrUnavailable, cl.err)
		} else {
			r.cfg.Logf("session renewed for %s until %s", c.Subject, cl.exp.UTC().Format(time.RFC3339))
		}
	case isTransient(rerr):
		cl.err = fmt.Errorf("%w: %v", ErrUnavailable, rerr)
		r.cfg.Logf("renewal for %s not completed: %v", c.Subject, rerr)
	default:
		// The provider answered and refused (invalid_grant: revoked, over, a
		// retired token replayed...): the family is over.
		delete(r.fams, c.Family)
		cl.err = ErrEnded
		r.cfg.Logf("renewal refused by the provider for %s, family ended: %v", c.Subject, rerr)
	}
	r.mu.Unlock()
	close(cl.done)
	return cl.token, cl.exp, cl.err
}

// isTransient says whether err is a failure to get an answer, or a provider
// that says it is momentarily unable (RFC 6749 section 4.1.2.1), rather than a
// refusal.
func isTransient(err error) bool {
	var e *rp.Error
	if errors.As(err, &e) {
		return e.Code == "server_error" || e.Code == "temporarily_unavailable"
	}
	// Not the provider's own answer: a network failure, a timeout, or a
	// malformed or non-JSON reply.
	return true
}
