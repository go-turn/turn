package session_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/oidc"
	"github.com/go-authn/rp"
	"github.com/go-turn/turn/internal/fakeidp"
	"github.com/go-turn/turn/session"
)

const allowed = "https://go-tex.github.io"

var key = []byte("0123456789abcdef0123456789abcdef")

type env struct {
	idp    *fakeidp.IdP
	srv    *httptest.Server
	signer *session.Signer
	login  *session.Login
}

func setup(t *testing.T, maxFlows int) *env {
	t.Helper()
	var h http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	idp := fakeidp.New(t, "turnd", "s3cret", srv.URL+"/callback")
	ctx := context.Background()
	p, err := rp.Discover(ctx, idp.Client(), idp.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := rp.NewClient(ctx, p, rp.Config{ClientID: "turnd", Secret: "s3cret", RedirectURI: srv.URL + "/callback"})
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := session.NewSigner(time.Hour, key)
	l, err := session.NewLogin(session.LoginConfig{Client: c, Signer: signer, Origins: []string{allowed, "http://localhost:8080"}, MaxFlows: maxFlows})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	l.Mount(mux)
	h = mux
	return &env{idp, srv, signer, l}
}

// browser is an HTTP client with a cookie jar that follows redirects (to the
// TLS provider, whose certificate it trusts).
func (e *env) browser(follow bool) *http.Client {
	jar, _ := cookiejar.New(nil)
	c := *e.idp.Client()
	c.Jar = jar
	if !follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &c
}

var pageRe = regexp.MustCompile(`var msg = (\{.*\}), target = ("[^"]*");`)

type result struct {
	status int
	hdr    http.Header
	msg    map[string]any
	target string
	body   string
}

func do(t *testing.T, c *http.Client, u string) result {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	r := result{status: resp.StatusCode, hdr: resp.Header, body: string(b)}
	if m := pageRe.FindStringSubmatch(string(b)); m != nil {
		if err := json.Unmarshal([]byte(m[1]), &r.msg); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal([]byte(m[2]), &r.target)
	}
	return r
}

func TestLoginEndToEnd(t *testing.T) {
	e := setup(t, 0)
	r := do(t, e.browser(true), e.srv.URL+"/login?origin="+url.QueryEscape(allowed))
	if r.status != 200 || r.msg["type"] != "turnd-session" {
		t.Fatalf("%d %v\n%s", r.status, r.msg, r.body)
	}
	if r.target != allowed || r.target == "*" || strings.Contains(r.body, `"*"`) {
		t.Fatalf("postMessage target %q", r.target)
	}
	if !strings.Contains(r.hdr.Get("Content-Security-Policy"), "script-src 'nonce-") || r.hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers %v", r.hdr)
	}
	c, err := e.signer.Verify(r.msg["token"].(string), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != session.Subject(e.idp.Issuer, "alice-sub") || strings.Contains(c.Subject, "alice") {
		t.Fatalf("subject %q", c.Subject)
	}
	if int64(r.msg["expires"].(float64)) != c.Expiry.Unix() {
		t.Fatal("expires mismatch")
	}
}

func TestLoginRefusesUnknownOrigin(t *testing.T) {
	e := setup(t, 0)
	for _, o := range []string{"", "*", "https://evil.example", allowed + ".evil.example", allowed + "/", "HTTPS://GO-TEX.GITHUB.IO", " " + allowed} {
		r := do(t, e.browser(false), e.srv.URL+"/login?origin="+url.QueryEscape(o))
		if r.status != http.StatusBadRequest || r.hdr.Get("Location") != "" {
			t.Errorf("origin %q: %d Location=%q", o, r.status, r.hdr.Get("Location"))
		}
	}
	// control: the allowlisted one redirects, to the provider.
	r := do(t, e.browser(false), e.srv.URL+"/login?origin="+url.QueryEscape(allowed))
	if r.status != http.StatusFound || !strings.HasPrefix(r.hdr.Get("Location"), e.idp.Issuer+"/authorize?") {
		t.Fatalf("control: %d %q", r.status, r.hdr.Get("Location"))
	}
	if strings.Contains(r.hdr.Get("Location"), "evil") || strings.Contains(r.hdr.Get("Location"), "go-tex.github.io") {
		t.Fatal("return origin leaked into the authorization URL")
	}
}

func TestCallbackBoundToBrowserAndSingleUse(t *testing.T) {
	e := setup(t, 0)
	a := e.browser(false)
	r := do(t, a, e.srv.URL+"/login?origin="+url.QueryEscape(allowed))
	// the provider answers (as a browser would follow it)
	auth := do(t, a, r.hdr.Get("Location"))
	cb := auth.hdr.Get("Location")
	if !strings.HasPrefix(cb, e.srv.URL+"/callback?") {
		t.Fatalf("callback %q", cb)
	}
	// another browser (no cookie) delivers the victim's redirect: refused, and the flow survives? no: it is burnt.
	if r := do(t, e.browser(false), cb); r.status != http.StatusBadRequest || r.msg != nil {
		t.Fatalf("cookieless callback: %d %v", r.status, r.msg)
	}
	// the flow was consumed by the refused attempt: the real browser cannot replay it either.
	if r := do(t, a, cb); r.status != http.StatusBadRequest {
		t.Fatalf("replay: %d", r.status)
	}
	// control: a fresh login in a browser with its cookie succeeds.
	b := e.browser(true)
	if r := do(t, b, e.srv.URL+"/login?origin="+url.QueryEscape(allowed)); r.msg["type"] != "turnd-session" {
		t.Fatalf("control: %v", r.msg)
	}
	// unknown state
	if r := do(t, b, e.srv.URL+"/callback?state=nope&code=x"); r.status != http.StatusBadRequest {
		t.Fatalf("unknown state: %d", r.status)
	}
}

func TestCallbackReplayAfterSuccess(t *testing.T) {
	e := setup(t, 0)
	a := e.browser(false)
	r := do(t, a, e.srv.URL+"/login?origin="+url.QueryEscape(allowed))
	cb := do(t, a, r.hdr.Get("Location")).hdr.Get("Location")
	if r := do(t, a, cb); r.msg["type"] != "turnd-session" {
		t.Fatalf("first: %v", r.msg)
	}
	if r := do(t, a, cb); r.status != http.StatusBadRequest || r.msg != nil {
		t.Fatalf("second: %d %v", r.status, r.msg)
	}
}

func TestProviderFailureGivesErrorNotToken(t *testing.T) {
	e := setup(t, 0)
	e.idp.BadNonce = true
	r := do(t, e.browser(true), e.srv.URL+"/login?origin="+url.QueryEscape(allowed))
	if r.msg["type"] != "turnd-error" || r.msg["token"] != nil || r.target != allowed {
		t.Fatalf("%d %v target=%q", r.status, r.msg, r.target)
	}
	// provider-reported error
	a := e.browser(false)
	l := do(t, a, e.srv.URL+"/login?origin="+url.QueryEscape(allowed))
	u, _ := url.Parse(l.hdr.Get("Location"))
	state := u.Query().Get("state")
	r = do(t, a, e.srv.URL+"/callback?error=access_denied&state="+url.QueryEscape(state))
	if r.msg["type"] != "turnd-error" || r.msg["token"] != nil {
		t.Fatalf("error param: %v", r.msg)
	}
}

func TestFlowCap(t *testing.T) {
	e := setup(t, 2)
	for i := 0; i < 2; i++ {
		if r := do(t, e.browser(false), e.srv.URL+"/login?origin="+url.QueryEscape(allowed)); r.status != http.StatusFound {
			t.Fatalf("login %d: %d", i, r.status)
		}
	}
	if r := do(t, e.browser(false), e.srv.URL+"/login?origin="+url.QueryEscape(allowed)); r.status != http.StatusServiceUnavailable {
		t.Fatalf("over the cap: %d", r.status)
	}
}

func TestNewLoginRefusals(t *testing.T) {
	e := setup(t, 0)
	_ = e
	if _, err := session.NewLogin(session.LoginConfig{}); err == nil {
		t.Error("empty config")
	}
	signer, _ := session.NewSigner(time.Hour, key)
	p, _ := rp.Discover(context.Background(), e.idp.Client(), e.idp.Issuer)
	c, _ := rp.NewClient(context.Background(), p, rp.Config{ClientID: "turnd", Secret: "s3cret", RedirectURI: "http://x/callback"})
	for _, o := range [][]string{nil, {"*"}, {""}} {
		if _, err := session.NewLogin(session.LoginConfig{Client: c, Signer: signer, Origins: o}); err == nil {
			t.Errorf("origins %q accepted", o)
		}
	}
}

func TestAuth(t *testing.T) {
	e := setup(t, 0)
	v, err := oidc.New(context.Background(), oidc.Config{Issuer: e.idp.Issuer, Audience: "turnd-api", Type: "at+jwt", Client: e.idp.Client()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a := &session.Auth{Signer: e.signer, AccessTokens: v, Now: func() time.Time { return now }}
	req := func(h string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		return r
	}
	st, _, _ := e.signer.Issue("sub1", now)
	if s, err := a.Subject(req("Bearer " + st)); err != nil || s != "sub1" {
		t.Fatalf("session: %q %v", s, err)
	}
	if s, err := a.Subject(req("bearer " + e.idp.AccessToken("turnd-api"))); err != nil || s != session.Subject(e.idp.Issuer, "alice-sub") {
		t.Fatalf("access token: %q %v", s, err)
	}
	// the same person has the same subject by either route
	cs, _ := a.Subject(req("Bearer " + e.idp.AccessToken("turnd-api")))
	if cs != session.Subject(e.idp.Issuer, "alice-sub") {
		t.Fatal("subject differs")
	}
	for name, h := range map[string]string{
		"none":             "",
		"basic":            "Basic abc",
		"empty":            "Bearer ",
		"garbage":          "Bearer not-a-token",
		"id token as AT":   "Bearer " + e.idp.IDToken("turnd-api"),
		"wrong audience":   "Bearer " + e.idp.AccessToken("someone-else"),
		"tampered session": "Bearer " + st[:len(st)-2] + "AA",
		"two tokens":       "Bearer " + st + " " + st,
	} {
		if _, err := a.Subject(req(h)); err != session.ErrUnauthorized {
			t.Errorf("%s: %v", name, err)
		}
	}
	later := &session.Auth{Signer: e.signer, Now: func() time.Time { return now.Add(2 * time.Hour) }}
	if _, err := later.Subject(req("Bearer " + st)); err != session.ErrUnauthorized {
		t.Errorf("expired: %v", err)
	}
	if _, err := (&session.Auth{Signer: e.signer}).Subject(req("Bearer " + e.idp.AccessToken("turnd-api"))); err != session.ErrUnauthorized {
		t.Errorf("access tokens not configured: %v", err)
	}
}
