// Package homepage serves turnd's home pages: GET / answers with a page that
// says what the host is, chosen by the Host header (the collaboration service's
// page, or the STUN/TURN relay's), in seven languages with a light, dark or
// system theme, under a strict Content-Security-Policy.
//
// The pages show only public facts handed in through Config: the transports
// and ports the relay advertises, and links. Nothing here can reach a secret, a
// client address, a count or a session: the handler reads nothing from the
// request but the Host, the language and theme cookies and Accept-Language.
//
// The look is go-authn/bridge's (bridge#104): Tailwind v4 standalone output,
// Lucide icons, a native language combo and a three-button theme switch that
// work without script. See web/PROVENANCE.txt for what is copied from where.
package homepage

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"strings"
)

// DefaultPlaygroundURL is the go-tex playground (hugo.toml baseURL plus
// /playground/, the URL its collaboration QR codes use).
const DefaultPlaygroundURL = "https://go-tex.github.io/playground/"

// Transport is one way a client can reach the relay: Kind is "udp", "tcp" or
// "tls", Port the public port as text.
type Transport struct{ Kind, Port string }

// Config is everything the pages say. All of it is public.
type Config struct {
	// CollabHost is the host (no port) of the collaboration service; TurnHosts
	// are the hosts of the relay. A request for a host in neither list gets the
	// collaboration page, as does a host in both.
	CollabHost string
	TurnHosts  []string
	// CollabURL is the collaboration service's origin, linked from the relay's
	// page; empty hides the link. PlaygroundURL defaults to DefaultPlaygroundURL.
	CollabURL     string
	PlaygroundURL string
	// Transports are listed on the relay's page; none hides the list.
	Transports []Transport
	// Secure marks the preference cookies Secure (the service is on https).
	Secure bool
}

// Home serves the pages.
type Home struct {
	cfg    Config
	collab map[string]bool // lower-cased hosts
	turn   map[string]bool
	assets map[string]asset
	tmpl   map[string]*template.Template
}

type asset struct {
	typ  string
	body []byte
}

//go:embed web/templates/*.html
var templateFS embed.FS

//go:embed web/static
var staticFS embed.FS

//go:embed web/icons/*.svg
var iconFS embed.FS

// icons maps a Lucide icon's name to the markup inside its <svg>: a fixed set
// of paths from the embedded files, never from a request.
var icons = func() map[string]string {
	m := map[string]string{}
	es, err := iconFS.ReadDir("web/icons")
	if err != nil {
		panic(err)
	}
	for _, e := range es {
		b, err := iconFS.ReadFile("web/icons/" + e.Name())
		if err != nil {
			panic(err)
		}
		s := string(b)
		o := strings.Index(s, "<svg")
		if o < 0 {
			panic("web/icons/" + e.Name() + " is not an <svg> file")
		}
		i := strings.Index(s[o:], ">") + o
		j := strings.LastIndex(s, "</svg>")
		if i < o || j < i {
			panic("web/icons/" + e.Name() + " is not an <svg> file")
		}
		m[strings.TrimSuffix(e.Name(), ".svg")] = strings.TrimSpace(s[i+1 : j])
	}
	return m
}()

func icon(name, class string) (template.HTML, error) {
	inner, ok := icons[name]
	if !ok {
		return "", errors.New("no icon " + name)
	}
	return template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="` +
		template.HTMLEscapeString(class) + `" aria-hidden="true" focusable="false">` + inner + `</svg>`), nil
}

func templatesFor(l string) *template.Template {
	text := func(key string) (string, error) {
		s, ok := lookup(l, key)
		if !ok {
			return "", fmt.Errorf("no %s text for %q", l, key)
		}
		return s, nil
	}
	return template.Must(template.New("").Funcs(template.FuncMap{
		"icon": icon,
		"t":    text,
		"tf": func(key string, args ...any) (string, error) {
			s, err := text(key)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf(s, args...), nil
		},
	}).ParseFS(templateFS, "web/templates/*.html"))
}

const uiJS = `"use strict";
(function () {
  var sel = document.getElementById("lang-select");
  if (!sel || !sel.form) { return; }
  var go = document.getElementById("lang-go");
  if (go) { go.hidden = true; }
  sel.addEventListener("change", function () { sel.form.submit(); });
})();
`

// New builds the pages.
func New(cfg Config) (*Home, error) {
	if cfg.PlaygroundURL == "" {
		cfg.PlaygroundURL = DefaultPlaygroundURL
	}
	h := &Home{cfg: cfg, collab: map[string]bool{}, turn: map[string]bool{}, assets: map[string]asset{}, tmpl: map[string]*template.Template{}}
	if cfg.CollabHost != "" {
		h.collab[normHost(cfg.CollabHost)] = true
	}
	for _, t := range cfg.TurnHosts {
		h.turn[normHost(t)] = true
	}
	for name, typ := range map[string]string{"app.css": "text/css; charset=utf-8", "brand.css": "text/css; charset=utf-8", "logo.svg": "image/svg+xml"} {
		b, err := fs.ReadFile(staticFS, "web/static/"+name)
		if err != nil {
			return nil, err
		}
		h.assets[name] = asset{typ, b}
	}
	for _, l := range languages {
		h.tmpl[l.Code] = templatesFor(l.Code)
	}
	return h, nil
}

// Mount registers the routes. "GET /{$}" matches the root path only: every
// other path stays the mux's 404. GET patterns also answer HEAD.
func (h *Home) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", h.home)
	mux.HandleFunc("GET /lang", func(w http.ResponseWriter, r *http.Request) {
		if c := r.URL.Query().Get("lang"); isLang(c) {
			h.setPref(w, r, langCookie, c)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("GET /theme", func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("theme"); isTheme(v) {
			h.setPref(w, r, themeCookie, v)
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("GET /ui.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(uiJS))
	})
	mux.HandleFunc("GET /assets/{name}", func(w http.ResponseWriter, r *http.Request) {
		a, ok := h.assets[r.PathValue("name")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", a.typ)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(a.body)
	})
}

// setPref sets a preference cookie (the choice and nothing else) and goes back
// to the page, the only one there is.
func (h *Home) setPref(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: 365 * 24 * 3600,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: h.cfg.Secure,
	})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// normHost is a Host header's host part, lower case, without port or trailing dot.
func normHost(hostport string) string {
	h := hostport
	if hh, _, err := net.SplitHostPort(hostport); err == nil {
		h = hh
	}
	return strings.TrimSuffix(strings.ToLower(strings.Trim(h, "[]")), ".")
}

// Page names which page a request's Host gets: "turn" for a relay host that is
// not also the collaboration host, else "collab" (an unknown host included).
func (h *Home) Page(hostport string) string {
	n := normHost(hostport)
	if h.turn[n] && !h.collab[n] {
		return "turn"
	}
	return "collab"
}

var transportLabels = map[string]string{"udp": "UDP", "tcp": "TCP", "tls": "TLS (turns:)"}

type transportView struct{ Label, Port string }

func (h *Home) home(w http.ResponseWriter, r *http.Request) {
	lang, theme := chooseLang(r), chooseTheme(r)
	name := h.Page(r.Host)
	data := map[string]any{
		"Lang": lang, "Tag": langTag(lang), "Languages": languages, "Theme": theme,
		"ThemeClass": "", "PlaygroundURL": h.cfg.PlaygroundURL, "CollabURL": h.cfg.CollabURL,
	}
	if theme != themeSystem {
		data["ThemeClass"] = theme
	}
	var tv []transportView
	for _, t := range h.cfg.Transports {
		tv = append(tv, transportView{transportLabels[t.Kind], t.Port})
	}
	data["Transports"] = tv
	title, _ := lookup(lang, name+".title")
	data["Title"] = title

	hd := w.Header()
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("Cache-Control", "no-store")
	hd.Add("Vary", "Accept-Language, Cookie, Host")
	// Render first: a template error must be a 500, not half a page.
	var b strings.Builder
	if err := h.tmpl[lang].ExecuteTemplate(&b, name, data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write([]byte(b.String()))
}
