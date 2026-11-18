package homepage

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

const (
	collabHost = "collab.example.org"
	turnHost   = "turn.example.org"
)

func testConfig() Config {
	return Config{
		CollabHost: collabHost, TurnHosts: []string{turnHost},
		CollabURL:  "https://" + collabHost,
		Transports: []Transport{{"udp", "3478"}, {"tcp", "3478"}, {"tls", "443"}},
		Secure:     true,
	}
}

func newServer(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	// What turnd already serves; the pages must not shadow it.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "login\n") })
	h.Mount(mux)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func do(t *testing.T, s *httptest.Server, method, host, path string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, s.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	c := *s.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestEveryHostAndLanguageIs200(t *testing.T) {
	s := newServer(t, testConfig())
	for _, host := range []string{collabHost, turnHost, "unknown.example.net"} {
		for _, l := range languages {
			resp, body := do(t, s, "GET", host, "/", map[string]string{"Cookie": "lang=" + l.Code})
			if resp.StatusCode != 200 {
				t.Fatalf("%s %s: %d", host, l.Code, resp.StatusCode)
			}
			if !strings.Contains(body, `<html lang="`+l.Tag+`"`) {
				t.Fatalf("%s %s: wrong <html lang>", host, l.Code)
			}
			if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Fatalf("content type %q", got)
			}
		}
	}
}

func TestPageByHost(t *testing.T) {
	s := newServer(t, testConfig())
	_, collab := do(t, s, "GET", collabHost, "/", map[string]string{"Cookie": "lang=en"})
	for _, want := range []string{"rendezvous and session service", `href="https://go-tex.github.io/playground/"`, `href="/login"`, "Sign in", "admits each guest"} {
		if !strings.Contains(collab, want) {
			t.Errorf("collab page lacks %q", want)
		}
	}
	if strings.Contains(collab, "STUN/TURN relay") {
		t.Error("collab page is the relay's")
	}
	_, turn := do(t, s, "GET", turnHost+":8081", "/", map[string]string{"Cookie": "lang=en"})
	for _, want := range []string{"STUN/TURN relay", "not a web service to browse", "UDP", "TCP", "TLS (turns:)", "port 3478", "port 443", `href="https://` + collabHost + `"`} {
		if !strings.Contains(turn, want) {
			t.Errorf("turn page lacks %q", want)
		}
	}
	if strings.Contains(turn, `href="/login"`) {
		t.Error("turn page offers the sign-in")
	}
	// An unknown host, and a host both lists name, get the collaboration page.
	_, unk := do(t, s, "GET", "Elsewhere.example.net", "/", map[string]string{"Cookie": "lang=en"})
	if unk != collab {
		t.Error("an unknown host does not get the collaboration page")
	}
	cfg := testConfig()
	cfg.TurnHosts = append(cfg.TurnHosts, collabHost)
	_, both := do(t, newServer(t, cfg), "GET", collabHost, "/", map[string]string{"Cookie": "lang=en"})
	if both != collab {
		t.Error("a host in both lists does not get the collaboration page")
	}
	// The host is compared without case, port and trailing dot.
	_, dot := do(t, s, "GET", "TURN.example.org.:443", "/", map[string]string{"Cookie": "lang=en"})
	if dot != turn {
		t.Error("TURN.example.org.:443 is not the relay's page")
	}
	// No transports configured: no list, still a page.
	cfg = testConfig()
	cfg.Transports = nil
	_, none := do(t, newServer(t, cfg), "GET", turnHost, "/", map[string]string{"Cookie": "lang=en"})
	if strings.Contains(none, "Transports offered") || !strings.Contains(none, "STUN/TURN relay") {
		t.Error("no-transport relay page")
	}
}

func TestHeadAndUnknownPaths(t *testing.T) {
	s := newServer(t, testConfig())
	for _, host := range []string{collabHost, turnHost} {
		resp, body := do(t, s, "HEAD", host, "/", nil)
		if resp.StatusCode != 200 || body != "" || resp.Header.Get("Content-Security-Policy") == "" {
			t.Fatalf("HEAD %s: %d %q", host, resp.StatusCode, body)
		}
	}
	for _, p := range []string{"/nope", "/index.html", "/assets/", "/assets/missing.css", "/lang/fr", "/x/", "/healthz/", "//", "/%2e%2e/"} {
		for _, m := range []string{"GET", "HEAD"} {
			if resp, _ := do(t, s, m, collabHost, p, nil); resp.StatusCode != 404 && resp.StatusCode != 301 && resp.StatusCode != 307 && resp.StatusCode != 308 { // the mux cleans "//" with a redirect
				t.Errorf("%s %s: %d", m, p, resp.StatusCode)
			}
		}
	}
	if resp, body := do(t, s, "GET", turnHost, "/nope", nil); resp.StatusCode != 404 || !strings.Contains(body, "404 page not found") {
		t.Errorf("/nope: %d %q", resp.StatusCode, body)
	}
	if resp, _ := do(t, s, "POST", collabHost, "/", nil); resp.StatusCode != 405 {
		t.Errorf("POST /: %d", resp.StatusCode)
	}
	// What was there stays there.
	if _, b := do(t, s, "GET", turnHost, "/healthz", nil); b != "ok\n" {
		t.Errorf("/healthz: %q", b)
	}
	if _, b := do(t, s, "GET", collabHost, "/login", nil); b != "login\n" {
		t.Errorf("/login: %q", b)
	}
}

func TestSecurityHeadersAndNoInlineCode(t *testing.T) {
	s := newServer(t, testConfig())
	const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	inline := regexp.MustCompile(`(?i)<script(\s[^>]*)?>[^<]|<style|\sstyle\s*=|\son[a-z]+\s*=|javascript:`)
	scripts := regexp.MustCompile(`(?i)<script[^>]*>`)
	for _, host := range []string{collabHost, turnHost} {
		for _, l := range languages {
			resp, body := do(t, s, "GET", host, "/", map[string]string{"Cookie": "lang=" + l.Code})
			if got := resp.Header.Get("Content-Security-Policy"); got != csp {
				t.Fatalf("CSP %q", got)
			}
			for k, v := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"} {
				if resp.Header.Get(k) != v {
					t.Errorf("%s = %q", k, resp.Header.Get(k))
				}
			}
			if m := inline.FindString(body); m != "" {
				t.Fatalf("%s %s: inline code %q", host, l.Code, m)
			}
			for _, tag := range scripts.FindAllString(body, -1) {
				if tag != `<script src="/ui.js">` {
					t.Fatalf("a script other than /ui.js: %s", tag)
				}
			}
			// Everything the page loads is its own.
			for _, m := range regexp.MustCompile(`(?:src|href)="([^"]*)"`).FindAllStringSubmatch(body, -1) {
				u := m[1]
				if strings.HasPrefix(u, "/") || strings.HasPrefix(u, "#") || strings.HasPrefix(u, "https://go-tex.github.io/playground/") || u == "https://"+collabHost {
					continue
				}
				t.Fatalf("%s: unexpected URL %q", host, u)
			}
		}
	}
	for _, a := range []string{"app.css", "brand.css", "logo.svg"} {
		resp, body := do(t, s, "GET", collabHost, "/assets/"+a, nil)
		if resp.StatusCode != 200 || body == "" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("/assets/%s: %d", a, resp.StatusCode)
		}
	}
	if resp, body := do(t, s, "GET", collabHost, "/ui.js", nil); resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "javascript") || body != uiJS {
		t.Errorf("/ui.js: %d", resp.StatusCode)
	}
}

// The page says nothing a request or the daemon's secrets could put in it.
func TestPageHoldsNoSecretAddressOrSession(t *testing.T) {
	secrets := []string{"client-s3cret", "session-key-0123456789abcdef0123456789", "turn-secret-0123456789abcdef",
		"eyJhbGciOiJIUzI1NiJ9.session.token", "room-0123456789abcdef0123456789abcdef", "alice@example.org", "/etc/turnd/", "203.0.113.77", "2001:db8::77"}
	// The config only carries public facts, but a hostile one is tried too: a
	// secret cannot be in what Config has no field for. The request is where a
	// leak could come from: its address, headers, cookies and query.
	s := newServer(t, testConfig())
	hdr := map[string]string{
		"X-Forwarded-For": "203.0.113.77", "X-Real-IP": "203.0.113.77", "Forwarded": "for=2001:db8::77",
		"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.session.token",
		"Cookie":        "lang=en; session=eyJhbGciOiJIUzI1NiJ9.session.token; room=room-0123456789abcdef0123456789abcdef; theme=dark",
		"Referer":       "https://go-tex.github.io/playground/#invite=client-s3cret",
		"User-Agent":    "alice@example.org",
	}
	q := "?room=room-0123456789abcdef0123456789abcdef&token=client-s3cret&lang=de&" + url.Values{"u": {"alice@example.org"}}.Encode()
	for _, host := range []string{collabHost, turnHost, "unknown.example.net"} {
		for _, p := range []string{"/", "/" + q} {
			resp, body := do(t, s, "GET", host, p, hdr)
			if resp.StatusCode != 200 {
				t.Fatalf("%s: %d", host, resp.StatusCode)
			}
			for _, sec := range secrets {
				if strings.Contains(body, sec) {
					t.Errorf("%s %s: the page contains %q", host, p, sec)
				}
			}
			// Nothing of the connection: not the client's address (127.0.0.1 here),
			// not the server's.
			for _, a := range []string{"127.0.0.1", "[::1]", s.Listener.Addr().String()} {
				if strings.Contains(body, a) {
					t.Errorf("%s: the page contains the address %q", host, a)
				}
			}
			for k := range resp.Header {
				if strings.EqualFold(k, "Set-Cookie") {
					t.Errorf("GET / sets a cookie")
				}
			}
		}
	}
	// The query string does not choose the language (Cookie, Accept-Language do).
	_, a := do(t, s, "GET", collabHost, "/", map[string]string{"Cookie": "lang=en"})
	_, b := do(t, s, "GET", collabHost, "/?lang=de", map[string]string{"Cookie": "lang=en"})
	if a != b {
		t.Error("the query string changed the page")
	}
}

func TestLanguageAndThemeChoice(t *testing.T) {
	s := newServer(t, testConfig())
	// Accept-Language picks among the seven by q, French by default.
	for al, want := range map[string]string{"": "fr", "de-DE,de;q=0.9,en;q=0.5": "de", "en;q=0.4, ja;q=0.8": "ja", "zh-Hans-CN": "zh-CN", "sv, fi": "fr", "ko;q=0": "fr", "es;q=2": "fr", "pt-BR,es;q=0.3": "es"} {
		_, body := do(t, s, "GET", collabHost, "/", map[string]string{"Accept-Language": al})
		if !strings.Contains(body, `<html lang="`+want+`"`) {
			t.Errorf("Accept-Language %q: not %s", al, want)
		}
	}
	// The cookie beats Accept-Language; a bad one is ignored.
	_, body := do(t, s, "GET", collabHost, "/", map[string]string{"Accept-Language": "de", "Cookie": "lang=ko"})
	if !strings.Contains(body, `<html lang="ko"`) {
		t.Error("cookie does not win")
	}
	_, body = do(t, s, "GET", collabHost, "/", map[string]string{"Accept-Language": "de", "Cookie": "lang=klingon"})
	if !strings.Contains(body, `<html lang="de"`) {
		t.Error("bad cookie is not ignored")
	}
	// The combo has the seven languages, the selected one marked.
	_, body = do(t, s, "GET", collabHost, "/", map[string]string{"Cookie": "lang=es"})
	if n := strings.Count(body, "<option "); n != 7 || !strings.Contains(body, `value="es" lang="es" selected`) {
		t.Errorf("combo: %d options", n)
	}
	// /lang and /theme set a preference cookie and go back, without script.
	resp, _ := do(t, s, "GET", collabHost, "/lang?lang=ja&next=https://evil.example/", nil)
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/" {
		t.Fatalf("/lang: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if c := resp.Header.Get("Set-Cookie"); !strings.HasPrefix(c, "lang=ja;") || !strings.Contains(c, "HttpOnly") || !strings.Contains(c, "SameSite=Lax") || !strings.Contains(c, "Secure") {
		t.Errorf("lang cookie %q", c)
	}
	if resp, _ := do(t, s, "GET", collabHost, "/lang?lang=xx", nil); resp.StatusCode != 404 {
		t.Errorf("/lang?lang=xx: %d", resp.StatusCode)
	}
	if resp, _ := do(t, s, "GET", collabHost, "/theme?theme=blue", nil); resp.StatusCode != 404 {
		t.Errorf("/theme?theme=blue: %d", resp.StatusCode)
	}
	resp, _ = do(t, s, "GET", collabHost, "/theme?theme=dark", nil)
	if resp.StatusCode != 303 || !strings.HasPrefix(resp.Header.Get("Set-Cookie"), "theme=dark;") {
		t.Errorf("/theme: %d %q", resp.StatusCode, resp.Header.Get("Set-Cookie"))
	}
	// The theme is drawn by the server, nothing flashes.
	for theme, class := range map[string]string{"dark": ` class="dark"`, "light": ` class="light"`, "system": ""} {
		_, body := do(t, s, "GET", collabHost, "/", map[string]string{"Cookie": "lang=en; theme=" + theme})
		if !strings.Contains(body, `<html lang="en"`+class+`><head>`) || !strings.Contains(body, `value="`+theme+`" title="`) || !strings.Contains(body, `aria-pressed="true"`) {
			t.Errorf("theme %s", theme)
		}
		if strings.Count(body, `aria-pressed="true"`) != 1 {
			t.Errorf("theme %s: not exactly one pressed button", theme)
		}
	}
	// Plain http: no Secure on the cookie.
	cfg := testConfig()
	cfg.Secure = false
	resp, _ = do(t, newServer(t, cfg), "GET", collabHost, "/lang?lang=fr", nil)
	if strings.Contains(resp.Header.Get("Set-Cookie"), "Secure") {
		t.Error("Secure cookie on plain http")
	}
}

func TestCatalogueIsComplete(t *testing.T) {
	for _, l := range languages {
		if len(catalogue[l.Code]) != len(catalogue[langFR]) {
			t.Errorf("%s has %d texts, French has %d", l.Code, len(catalogue[l.Code]), len(catalogue[langFR]))
		}
		for k := range catalogue[langFR] {
			if s, ok := lookup(l.Code, k); !ok || strings.TrimSpace(s) == "" {
				t.Errorf("%s lacks %q", l.Code, k)
			}
		}
	}
	if len(catalogue) != len(languages) {
		t.Errorf("%d catalogues, %d languages", len(catalogue), len(languages))
	}
	// A printf text keeps its verb in every language.
	for _, l := range languages {
		if s, _ := lookup(l.Code, "turn.port"); strings.Count(s, "%s") != 1 {
			t.Errorf("%s turn.port %q", l.Code, s)
		}
	}
}

// app.css is Tailwind's output for bridge's templates: it defines only the
// utilities those used. A class these templates use that it lacks would draw
// as nothing, silently.
func TestTemplateClassesExistInCSS(t *testing.T) {
	css, err := staticFS.ReadFile("web/static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	es, _ := templateFS.ReadDir("web/templates")
	classRe := regexp.MustCompile(`class="([^"]*)"`)
	esc := strings.NewReplacer(":", `\:`, "/", `\/`, ".", `\.`, "[", `\[`, "]", `\]`, "%", `\%`, "(", `\(`, ")", `\)`, ",", `\,`)
	// Component classes and the ones set by the layout's own CSS, not utilities.
	for _, e := range es {
		b, _ := templateFS.ReadFile("web/templates/" + e.Name())
		for _, m := range classRe.FindAllStringSubmatch(string(b), -1) {
			for _, c := range strings.Fields(m[1]) {
				if strings.Contains(c, "{{") || strings.Contains(c, "}}") {
					continue
				}
				if !strings.Contains(string(css), "."+esc.Replace(c)) {
					t.Errorf("%s: class %q is not in app.css", e.Name(), c)
				}
			}
		}
	}
}

func TestIconsAreTheCopiedLucideSet(t *testing.T) {
	for _, n := range []string{"sun", "moon", "monitor", "chevron-down", "circle-check", "key-round", "user-round", "monitor-smartphone", "shield-check", "plug", "laptop"} {
		if _, err := icon(n, "size-4"); err != nil {
			t.Error(err)
		}
	}
	if _, err := icon("nope", ""); err == nil {
		t.Error("an unknown icon did not fail")
	}
}
