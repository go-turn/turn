package main

import (
	"strings"
	"sync"
	"testing"
	"time"

	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func renew(t *testing.T, rpc turnv1.TurndClient, token string) (*turnv1.RenewSessionResponse, error) {
	t.Helper()
	return rpc.RenewSession(rctx(t, token), &turnv1.RenewSessionRequest{})
}

func mustCode(t *testing.T, what string, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("%s: %v, want %v", what, err, want)
	}
}

func TestRenewSessionEndToEnd(t *testing.T) {
	d := run(t)
	d.idp.SetRefresh(true)
	tok, _ := d.login(t)
	rpc := d.dial(t, origin)

	r1, err := renew(t, rpc, tok)
	if err != nil || r1.Token == "" || r1.Token == tok || r1.Expires <= time.Now().Unix() {
		t.Fatalf("renew: %v %v", r1, err)
	}
	// The new token is a session: it opens credentials.
	if _, err := rpc.Credentials(rctx(t, r1.Token), &turnv1.CredentialsRequest{}); err != nil {
		t.Fatalf("the renewed token is not a session: %v", err)
	}
	// Chain: the new token renews; the OLD one still does (it is still valid);
	// neither replays a retired refresh token at the provider.
	r2, err := renew(t, rpc, r1.Token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := renew(t, rpc, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := renew(t, rpc, r2.Token); err != nil {
		t.Fatal(err)
	}
	if got := d.idp.Refreshes(); got != 4 {
		t.Fatalf("provider saw %d refreshes, want 4", got)
	}
	if got := d.idp.Replays(); got != 0 {
		t.Fatalf("a retired refresh token was replayed %d time(s)", got)
	}
	if s := d.idp.LastScope(); s != "openid offline_access" {
		t.Fatalf("login scope %q", s)
	}
	// The refresh token never reached the browser.
	if strings.Contains(r1.Token, "refresh") || strings.Contains(d.errs.String(), r1.Token) {
		t.Fatal("a token reached a log")
	}
	if !strings.Contains(d.errs.String(), "session renewed for u") {
		t.Fatalf("no renewal outcome in the log:\n%s", d.errs)
	}
}

func TestRenewSessionRevokedAtTheProviderEndsTheFamily(t *testing.T) {
	d := run(t)
	d.idp.SetRefresh(true)
	tok, _ := d.login(t)
	rpc := d.dial(t, origin)
	if _, err := renew(t, rpc, tok); err != nil {
		t.Fatal(err)
	}
	d.idp.RevokeAll()
	_, err := renew(t, rpc, tok)
	mustCode(t, "renew after revocation", err, codes.Unauthenticated)
	seen := d.idp.Refreshes()
	// Ended for good: no second question to the provider, whatever token is brought.
	_, err = renew(t, rpc, tok)
	mustCode(t, "renew after the family ended", err, codes.Unauthenticated)
	if d.idp.Refreshes() != seen {
		t.Fatal("the provider was asked again after the family ended")
	}
	if !strings.Contains(d.errs.String(), "family ended") {
		t.Fatalf("the refusal is not in the log:\n%s", d.errs)
	}
}

func TestRenewSessionNotRenewable(t *testing.T) {
	d := run(t) // the provider issues no refresh token
	tok, _ := d.login(t)
	rpc := d.dial(t, origin)
	_, err := renew(t, rpc, tok)
	mustCode(t, "token without a family", err, codes.Unauthenticated)
	_, err = renew(t, rpc, "")
	mustCode(t, "no token", err, codes.Unauthenticated)
	_, err = renew(t, rpc, "t2.AAAA.AAAA")
	mustCode(t, "garbage", err, codes.Unauthenticated)
	if !strings.Contains(d.errs.String(), "no refresh token") {
		t.Fatalf("the missing refresh token is not logged:\n%s", d.errs)
	}
}

func TestRenewSessionConcurrentSpendsOnce(t *testing.T) {
	d := run(t)
	d.idp.SetRefresh(true)
	tok, _ := d.login(t)
	d.idp.SetRefreshDelay(300 * time.Millisecond)
	rpc := d.dial(t, origin)
	const n = 6
	out := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := renew(t, rpc, tok)
			errs[i] = err
			if err == nil {
				out[i] = r.Token
			}
		}()
	}
	wg.Wait()
	for i := range out {
		if errs[i] != nil || out[i] != out[0] {
			t.Fatalf("caller %d: %v %q", i, errs[i], out[i])
		}
	}
	if got := d.idp.Refreshes(); got != 1 || d.idp.Replays() != 0 {
		t.Fatalf("%d concurrent renewals made %d refreshes, %d replays; want 1 and 0", n, got, d.idp.Replays())
	}
}

func TestRenewSessionOff(t *testing.T) {
	d := run(t, "--session-renewal-lifetime", "0")
	d.idp.SetRefresh(true)
	tok, _ := d.login(t)
	_, err := renew(t, d.dial(t, origin), tok)
	mustCode(t, "renewal off", err, codes.Unimplemented)
	if s := d.idp.LastScope(); s != "openid" {
		t.Fatalf("scope %q with renewal off, want openid alone", s)
	}
}
