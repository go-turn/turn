package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/go-authn/rp"
)

// Subject is the opaque, stable identifier turnd uses for a person: a hash of
// issuer and "sub", never a name. It ends up in TURN usernames, which an
// eavesdropper sees (draft-uberti-behave-turn-rest-00 §6).
func Subject(issuer, sub string) string {
	h := sha256.Sum256([]byte(issuer + "\x00" + sub))
	return "u" + base64.RawURLEncoding.EncodeToString(h[:])[:22]
}

// LoginConfig configures [NewLogin].
type LoginConfig struct {
	Client *rp.Client
	Signer *Signer
	// Origins is the allowlist of origins ("https://go-tex.github.io") that may
	// open /login and receive the token by postMessage. Compared exactly; the
	// popup's return target comes from here and nowhere else.
	Origins []string
	// Secure marks the flow cookie Secure (set it when the public URL is https).
	Secure bool
	// FlowTTL is how long a login may take (default 10 minutes); MaxFlows bounds
	// the logins in progress (default 4096).
	FlowTTL  time.Duration
	MaxFlows int
	Now      func() time.Time
	// Renewer, when set, keeps the provider's refresh token of each login
	// server side and issues renewable session tokens. A login that comes back
	// without a refresh token still gets a session, one that cannot be renewed.
	Renewer *Renewer
	// Logf receives one line per callback outcome: the pseudonymous subject
	// on success, the reason on a refusal, never a code, token or cookie.
	// Without it the operator cannot tell a login that worked from one that
	// failed: the popup shows the same "You can close this window" for both
	// when it has no opener. Nil logs nothing.
	Logf func(format string, args ...any)
}

// Login serves /login and /callback.
type Login struct {
	cfg   LoginConfig
	mu    sync.Mutex
	flows map[string]flow
}

type flow struct {
	f       rp.Flow
	origin  string
	bind    [sha256.Size]byte
	expires time.Time
}

const cookieName = "turnd_flow"

// NewLogin validates cfg.
func NewLogin(cfg LoginConfig) (*Login, error) {
	if cfg.Client == nil || cfg.Signer == nil {
		return nil, errors.New("session: login needs a client and a signer")
	}
	if len(cfg.Origins) == 0 {
		return nil, errors.New("session: login needs at least one allowed origin")
	}
	for _, o := range cfg.Origins {
		if o == "" || o == "*" {
			return nil, errors.New("session: an allowed origin must be exact, never * or empty")
		}
	}
	if cfg.FlowTTL <= 0 {
		cfg.FlowTTL = 10 * time.Minute
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = 4096
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Login{cfg: cfg, flows: map[string]flow{}}, nil
}

// Mount registers GET /login and GET /callback on mux.
func (l *Login) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", l.login)
	mux.HandleFunc("GET /callback", l.callback)
}

func (l *Login) sweepLocked(now time.Time) {
	for k, v := range l.flows {
		if !v.expires.After(now) {
			delete(l.flows, k)
		}
	}
}

func (l *Login) login(w http.ResponseWriter, r *http.Request) {
	origin := r.URL.Query().Get("origin")
	if !slices.Contains(l.cfg.Origins, origin) {
		// Never a redirect: an unknown return origin is a 400, not a bounce.
		http.Error(w, "origin not allowed", http.StatusBadRequest)
		return
	}
	f := rp.NewFlow()
	var cookie [16]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cv := base64.RawURLEncoding.EncodeToString(cookie[:])
	now := l.cfg.Now()
	l.mu.Lock()
	l.sweepLocked(now)
	if len(l.flows) >= l.cfg.MaxFlows {
		l.mu.Unlock()
		w.Header().Set("Retry-After", "30")
		http.Error(w, "too many logins in progress", http.StatusServiceUnavailable)
		return
	}
	l.flows[f.State] = flow{f: f, origin: origin, bind: sha256.Sum256([]byte(cv)), expires: now.Add(l.cfg.FlowTTL)}
	l.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: cv, Path: "/callback", MaxAge: int(l.cfg.FlowTTL / time.Second),
		HttpOnly: true, Secure: l.cfg.Secure, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, l.cfg.Client.AuthCodeURL(f, nil), http.StatusFound)
}

func (l *Login) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	l.mu.Lock()
	fl, ok := l.flows[state]
	delete(l.flows, state) // single use, whatever follows
	l.mu.Unlock()
	if !ok || !fl.expires.After(l.cfg.Now()) {
		l.cfg.Logf("login refused: unknown or expired flow")
		http.Error(w, "login expired or unknown; start again", http.StatusBadRequest)
		return
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		l.cfg.Logf("login refused: no flow cookie (not started in this browser)")
		http.Error(w, "login not started in this browser", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte(c.Value))
	if subtle.ConstantTimeCompare(sum[:], fl.bind[:]) != 1 {
		l.cfg.Logf("login refused: flow cookie does not match (not started in this browser)")
		http.Error(w, "login not started in this browser", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/callback", MaxAge: -1, HttpOnly: true, Secure: l.cfg.Secure, SameSite: http.SameSiteLaxMode})
	if e := q.Get("error"); e != "" {
		// The provider's error code is text from the request: quoted and cut,
		// so it cannot forge a log line.
		l.cfg.Logf("login refused by the provider: %.64q", e)
		l.page(w, fl.origin, message{Type: "turnd-error", Error: "access_denied"})
		return
	}
	if err := l.cfg.Client.CheckIssuer(q); err != nil || q.Get("code") == "" {
		l.cfg.Logf("login refused: issuer check or missing code: %v", err)
		l.page(w, fl.origin, message{Type: "turnd-error", Error: "login_failed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	pt, id, err := l.cfg.Client.Exchange(ctx, q.Get("code"), fl.f)
	if err != nil || id == nil {
		l.cfg.Logf("login refused: code exchange: %v", err)
		l.page(w, fl.origin, message{Type: "turnd-error", Error: "login_failed"})
		return
	}
	subject := Subject(id.Issuer(), id.Subject())
	var tok string
	var exp time.Time
	renewable := false
	if l.cfg.Renewer != nil && pt != nil && pt.RefreshToken != "" {
		// The refresh token stays here; the browser gets a session token only.
		if fam, ferr := l.cfg.Renewer.Open(subject, pt.RefreshToken); ferr == nil {
			tok, exp, err = l.cfg.Signer.IssueRenewable(subject, fam, l.cfg.Now())
			renewable = true
		} else {
			l.cfg.Logf("login: not renewable: %v", ferr)
		}
	} else if l.cfg.Renewer != nil {
		l.cfg.Logf("login: the provider issued no refresh token (enable refresh_lifetime for this client): session not renewable")
	}
	if !renewable {
		tok, exp, err = l.cfg.Signer.Issue(subject, l.cfg.Now())
	}
	if err != nil {
		l.cfg.Logf("login refused: issuing the session: %v", err)
		l.page(w, fl.origin, message{Type: "turnd-error", Error: "login_failed"})
		return
	}
	l.cfg.Logf("login: session issued to %s for origin %s, until %s, renewable: %t", subject, fl.origin, exp.UTC().Format(time.RFC3339), renewable)
	l.page(w, fl.origin, message{Type: "turnd-session", Token: tok, Expires: exp.Unix()})
}

type message struct {
	Type    string `json:"type"`
	Token   string `json:"token,omitempty"`
	Expires int64  `json:"expires,omitempty"`
	Error   string `json:"error,omitempty"`
}

var pageTmpl = template.Must(template.New("p").Parse(`<!doctype html>
<meta charset="utf-8"><title>turnd</title>
<p id="m">Signing in…</p>
<script nonce="{{.Nonce}}">
var msg = {{.Msg}}, target = {{.Target}};
if (window.opener) { window.opener.postMessage(msg, target); window.close(); }
else { document.getElementById("m").textContent = "You can close this window."; }
</script>
`))

// page serves the page that hands msg to window.opener, and only to the exact
// allowlisted origin: postMessage's targetOrigin is never "*".
func (l *Login) page(w http.ResponseWriter, origin string, m message) {
	var n [16]byte
	_, _ = rand.Read(n[:])
	nonce := base64.RawURLEncoding.EncodeToString(n[:])
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; base-uri 'none'; form-action 'none'")
	msg, _ := json.Marshal(m)
	tgt, _ := json.Marshal(origin)
	// html/template's JS context escapes a json.RawMessage-like value safely only
	// when it is given as data; pass the strings and let it quote them.
	_ = pageTmpl.Execute(w, struct {
		Nonce  string
		Msg    template.JS
		Target template.JS
	}{nonce, template.JS(msg), template.JS(tgt)}) //nolint:gosec // json.Marshal output escapes <, > and &.
}
