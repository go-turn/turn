// Package fakeidp is an in-process OpenID provider for tests, over TLS
// (httptest). It is as strict as the parts of a real one that turnd relies on:
// exact redirect URI, PKCE S256 only, client_secret_basic, single-use codes.
//
// go-authn/rp and go-authn/oidc have the same kind of provider, but inside
// their _test.go files, where no other module can import it; this one is
// adapted from rp's idp_test.go (BSD-3-Clause, go-authn).
package fakeidp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-authn/rp"
)

// IdP is the provider. Set the exported fields before the first login.
type IdP struct {
	t      *testing.T
	Srv    *httptest.Server
	key    *ecdsa.PrivateKey
	Issuer string

	ClientID, Secret, Redirect string
	// Subject is the "sub" every login gets.
	Subject string
	// BadNonce makes the ID token carry a nonce that is not the login's.
	BadNonce bool

	mu    sync.Mutex
	codes map[string]grant
}

type grant struct{ challenge, nonce, redirect string }

// New starts a provider for one confidential client.
func New(t *testing.T, clientID, secret, redirect string) *IdP {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &IdP{t: t, key: k, ClientID: clientID, Secret: secret, Redirect: redirect, Subject: "alice-sub", codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.Srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.Srv.Close)
	p.Issuer = p.Srv.URL
	return p
}

// Client is an HTTP client that trusts the provider's certificate.
func (p *IdP) Client() *http.Client { return p.Srv.Client() }

func (p *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.Issuer, "authorization_endpoint": p.Issuer + "/authorize",
		"token_endpoint": p.Issuer + "/token", "jwks_uri": p.Issuer + "/jwks",
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
		"id_token_signing_alg_values_supported":          []string{"ES256"},
	})
}

func (p *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
		"x": b64(pub.X.FillBytes(make([]byte, 32))), "y": b64(pub.Y.FillBytes(make([]byte, 32))),
	}}})
}

func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.ClientID || q.Get("redirect_uri") != p.Redirect || q.Get("response_type") != "code" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := randStr()
	p.mu.Lock()
	p.codes[code] = grant{q.Get("code_challenge"), q.Get("nonce"), q.Get("redirect_uri")}
	p.mu.Unlock()
	v := url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {p.Issuer}}
	http.Redirect(w, r, q.Get("redirect_uri")+"?"+v.Encode(), http.StatusFound)
}

func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id, secret, basic := r.BasicAuth()
	id, _ = url.QueryUnescape(id)
	secret, _ = url.QueryUnescape(secret)
	if !basic || id != p.ClientID || secret != p.Secret || r.PostForm.Get("grant_type") != "authorization_code" {
		tokenErr(w, "invalid_client")
		return
	}
	p.mu.Lock()
	g, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	if !ok || g.redirect != r.PostForm.Get("redirect_uri") || rp.Challenge(r.PostForm.Get("code_verifier")) != g.challenge {
		tokenErr(w, "invalid_grant")
		return
	}
	nonce := g.nonce
	if p.BadNonce {
		nonce = "not-" + nonce
	}
	idc := map[string]any{"iss": p.Issuer, "sub": p.Subject, "aud": p.ClientID, "nonce": nonce,
		"preferred_username": "alice", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": p.AccessToken(p.ClientID), "token_type": "Bearer",
		"expires_in": 300, "id_token": p.sign("JWT", idc)})
}

// AccessToken is an RFC 9068 access token (typ at+jwt) for audience aud.
func (p *IdP) AccessToken(aud string) string {
	return p.sign("at+jwt", map[string]any{"iss": p.Issuer, "sub": p.Subject, "aud": aud, "client_id": p.ClientID,
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "jti": randStr()})
}

// IDToken is an ID token (typ JWT) with the same audience rules, for the test
// that an ID token is not taken for an access token.
func (p *IdP) IDToken(aud string) string {
	return p.sign("JWT", map[string]any{"iss": p.Issuer, "sub": p.Subject, "aud": aud,
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()})
}

func (p *IdP) sign(typ string, claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "k1", "typ": typ})
	c, _ := json.Marshal(claims)
	in := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, sum[:])
	if err != nil {
		p.t.Fatal(err)
	}
	return in + "." + b64(append(pad32(r), pad32(s)...))
}

func pad32(n *big.Int) []byte { return n.FillBytes(make([]byte, 32)) }
func b64(b []byte) string     { return base64.RawURLEncoding.EncodeToString(b) }

func randStr() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b64(b)
}

func tokenErr(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
