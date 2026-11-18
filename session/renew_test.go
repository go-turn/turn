package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authn/rp"
)

type fakeRefresher struct {
	mu    sync.Mutex
	seen  []string // refresh tokens presented, in order
	n     int
	err   error
	delay time.Duration
}

func (f *fakeRefresher) Refresh(_ context.Context, rt string, _ rp.For) (*rp.Token, error) {
	time.Sleep(f.delay)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, rt)
	if f.err != nil {
		return nil, f.err
	}
	f.n++
	return &rp.Token{AccessToken: "at", RefreshToken: "rt" + string(rune('0'+f.n))}, nil
}

type renewEnv struct {
	r   *Renewer
	s   *Signer
	ref *fakeRefresher
	now atomic.Int64 // unix seconds
}

func newRenewEnv(t *testing.T, mut func(*RenewConfig)) *renewEnv {
	t.Helper()
	e := &renewEnv{ref: &fakeRefresher{}}
	e.now.Store(1_800_000_000)
	var err error
	if e.s, err = NewSigner(time.Hour, []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	cfg := RenewConfig{Refresher: e.ref, Signer: e.s, Lifetime: 24 * time.Hour,
		Now: func() time.Time { return time.Unix(e.now.Load(), 0) }}
	if mut != nil {
		mut(&cfg)
	}
	if e.r, err = NewRenewer(cfg); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *renewEnv) advance(d time.Duration) { e.now.Add(int64(d / time.Second)) }

func (e *renewEnv) login(t *testing.T, subject string) string {
	t.Helper()
	fam, err := e.r.Open(subject, "rt0")
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := e.s.IssueRenewable(subject, fam, time.Unix(e.now.Load(), 0))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRenewRotatesAndNeverReplays(t *testing.T) {
	e := newRenewEnv(t, nil)
	tok := e.login(t, "alice")
	t1, exp, err := e.r.Renew(context.Background(), tok)
	if err != nil || t1 == "" || t1 == tok {
		t.Fatalf("renew: %q %v", t1, err)
	}
	if want := time.Unix(e.now.Load(), 0).Add(time.Hour); !exp.Equal(want) {
		t.Fatalf("expiry %v, want %v", exp, want)
	}
	c, err := e.s.Verify(t1, time.Unix(e.now.Load(), 0))
	if err != nil || c.Subject != "alice" || c.Family.IsZero() {
		t.Fatalf("new token: %+v %v", c, err)
	}
	// The same family renews again, with the OLD session token too, and each
	// call spends the CURRENT refresh token, never a retired one.
	if _, _, err := e.r.Renew(context.Background(), t1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.r.Renew(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	want := []string{"rt0", "rt1", "rt2"}
	if len(e.ref.seen) != 3 || e.ref.seen[0] != want[0] || e.ref.seen[1] != want[1] || e.ref.seen[2] != want[2] {
		t.Fatalf("refresh tokens spent: %v, want %v", e.ref.seen, want)
	}
}

func TestRenewGrace(t *testing.T) {
	e := newRenewEnv(t, nil)
	tok := e.login(t, "alice")
	e.advance(time.Hour + 4*time.Minute) // expired, inside the 5 minute grace
	if _, _, err := e.r.Renew(context.Background(), tok); err != nil {
		t.Fatalf("inside the grace: %v", err)
	}
	e.advance(10 * time.Minute) // the same old token is now beyond it
	if _, _, err := e.r.Renew(context.Background(), tok); !errors.Is(err, ErrEnded) {
		t.Fatalf("beyond the grace: %v", err)
	}
	if len(e.ref.seen) != 1 {
		t.Fatalf("the provider was asked %d times, want 1 (a refusal before it)", len(e.ref.seen))
	}
	// Control: Verify, which every other endpoint uses, never takes an expired token.
	if _, err := e.s.Verify(tok, time.Unix(e.now.Load(), 0).Add(-9*time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify of an expired token: %v", err)
	}
}

func TestRenewRefusalEndsFamily(t *testing.T) {
	for _, code := range []string{"invalid_grant", "invalid_client", "invalid_scope"} {
		e := newRenewEnv(t, nil)
		tok := e.login(t, "alice")
		e.ref.err = &rp.Error{Code: code}
		if _, _, err := e.r.Renew(context.Background(), tok); !errors.Is(err, ErrEnded) {
			t.Fatalf("%s: %v", code, err)
		}
		if e.r.Families() != 0 {
			t.Fatalf("%s: the family survived", code)
		}
		// Even if the provider would now say yes, the family is gone.
		e.ref.err = nil
		if _, _, err := e.r.Renew(context.Background(), tok); !errors.Is(err, ErrEnded) {
			t.Fatalf("%s: renewed after the family ended: %v", code, err)
		}
		if len(e.ref.seen) != 1 {
			t.Fatalf("%s: asked %d times", code, len(e.ref.seen))
		}
	}
}

func TestRenewTransientFailureKeepsFamily(t *testing.T) {
	for name, err := range map[string]error{
		"network": errors.New("dial tcp: connection refused"),
		"503":     errors.New("rp: token endpoint: 503 Service Unavailable"),
		"server":  &rp.Error{Code: "server_error"},
		"busy":    &rp.Error{Code: "temporarily_unavailable"},
	} {
		e := newRenewEnv(t, nil)
		tok := e.login(t, "alice")
		e.ref.err = err
		if _, _, got := e.r.Renew(context.Background(), tok); !errors.Is(got, ErrUnavailable) {
			t.Fatalf("%s: %v", name, got)
		}
		e.ref.err = nil
		if _, _, got := e.r.Renew(context.Background(), tok); got != nil {
			t.Fatalf("%s: the retry failed: %v", name, got)
		}
		// The refresh token was not spent by the failure: the retry presents rt0 again.
		if len(e.ref.seen) != 2 || e.ref.seen[1] != "rt0" {
			t.Fatalf("%s: spent %v", name, e.ref.seen)
		}
	}
}

func TestRenewRefusesWhatIsNotRenewable(t *testing.T) {
	e := newRenewEnv(t, nil)
	now := time.Unix(e.now.Load(), 0)
	v1, _, _ := e.s.Issue("alice", now) // a v0.4.0 token: no family
	otherKey, _ := NewSigner(time.Hour, []byte("fedcba9876543210fedcba9876543210"))
	fam, _ := e.r.Open("alice", "rt0")
	forged, _, _ := otherKey.IssueRenewable("alice", fam, now)
	var unknown Family
	unknown[0] = 1
	lost, _, _ := e.s.IssueRenewable("alice", unknown, now) // a family turnd does not hold (restart)
	other, _, _ := e.s.IssueRenewable("mallory", fam, now)  // alice's family, another subject
	for name, tok := range map[string]string{"v1 token": v1, "forged": forged, "unknown family": lost,
		"other subject": other, "empty": "", "garbage": "t2.x.y", "access token": "eyJhbGciOi.x.y"} {
		if _, _, err := e.r.Renew(context.Background(), tok); !errors.Is(err, ErrEnded) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(e.ref.seen) != 0 {
		t.Fatalf("the provider was asked for a token that is not renewable: %v", e.ref.seen)
	}
}

func TestRenewFamilyLifetime(t *testing.T) {
	e := newRenewEnv(t, nil) // Lifetime 24 h
	tok := e.login(t, "alice")
	for i := 0; i < 23; i++ { // renew every hour: the lifetime counts from the login
		e.advance(time.Hour)
		var err error
		if tok, _, err = e.r.Renew(context.Background(), tok); err != nil {
			t.Fatalf("hour %d: %v", i+1, err)
		}
	}
	e.advance(time.Hour + time.Second)
	if _, _, err := e.r.Renew(context.Background(), tok); !errors.Is(err, ErrEnded) {
		t.Fatalf("past the family lifetime: %v", err)
	}
	if e.r.Families() != 0 {
		t.Fatal("the over family was kept")
	}
}

func TestRenewConcurrentSpendsOnce(t *testing.T) {
	e := newRenewEnv(t, nil)
	e.ref.delay = 200 * time.Millisecond
	tok := e.login(t, "alice")
	const n = 8
	toks := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toks[i], _, errs[i] = e.r.Renew(context.Background(), tok)
		}()
	}
	wg.Wait()
	for i := range toks {
		if errs[i] != nil || toks[i] == "" || toks[i] != toks[0] {
			t.Fatalf("caller %d: %q %v (first %q)", i, toks[i], errs[i], toks[0])
		}
	}
	if len(e.ref.seen) != 1 {
		t.Fatalf("refresh token spent %d times by %d concurrent renewals: %v", len(e.ref.seen), n, e.ref.seen)
	}
}

func TestRenewStoreIsBounded(t *testing.T) {
	e := newRenewEnv(t, func(c *RenewConfig) { c.MaxFamilies = 3 })
	var first string
	for i := 0; i < 5; i++ {
		tok := e.login(t, "alice")
		if i == 0 {
			first = tok
		}
		e.advance(time.Minute) // later families end later: the earliest is dropped
		if got := e.r.Families(); got > 3 {
			t.Fatalf("%d families held, cap 3", got)
		}
	}
	if _, _, err := e.r.Renew(context.Background(), first); !errors.Is(err, ErrEnded) {
		t.Fatalf("the dropped family renewed: %v", err)
	}
}

func TestRenewExpiredFamiliesAreSwept(t *testing.T) {
	e := newRenewEnv(t, nil)
	e.login(t, "alice")
	e.advance(25 * time.Hour)
	e.login(t, "bob") // Open sweeps
	if got := e.r.Families(); got != 1 {
		t.Fatalf("%d families, want 1", got)
	}
}

func TestTokenV2RoundTripAndV1StillVerifies(t *testing.T) {
	s, _ := NewSigner(time.Hour, []byte("0123456789abcdef0123456789abcdef"))
	now := time.Unix(1_800_000_000, 0)
	var fam Family
	fam[3] = 9
	t2, _, err := s.IssueRenewable("alice", fam, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Verify(t2, now)
	if err != nil || c.Family != fam || c.Subject != "alice" {
		t.Fatalf("%+v %v", c, err)
	}
	t1, _, _ := s.Issue("alice", now)
	if c, err := s.Verify(t1, now); err != nil || !c.Family.IsZero() {
		t.Fatalf("v1: %+v %v", c, err)
	}
	if _, _, err := s.IssueRenewable("alice", Family{}, now); err == nil {
		t.Fatal("a zero family was issued")
	}
	// A v1 payload relabelled as v2 (or the reverse) fails its MAC: the labels differ.
	if _, err := s.Verify("t2."+t1[len("t1."):], now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relabelled: %v", err)
	}
}
