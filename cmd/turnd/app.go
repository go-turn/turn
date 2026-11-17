package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/go-authn/oidc"
	"github.com/go-authn/rp"
	"github.com/go-turn/turn/creds"
	"github.com/go-turn/turn/rendezvous"
	"github.com/go-turn/turn/session"
)

// config is everything turnd is told. Every secret is a FILE path: a secret in
// a flag shows in the process list, one in the environment is inherited.
type config struct {
	Issuer, ClientID, ClientSecretFile string
	AccessTokenAudience                string
	SessionKeyFiles, TurnSecretFiles   []string
	Origins                            []string
	PublicURL, Listen                  string
	TLSCertFile, TLSKeyFile            string
	Realm                              string
	STUNURLs, TURNURLs                 []string
	SessionTTL, CredTTL                time.Duration
	Limits                             rendezvous.Limits
	Relay                              relayOptions
}

// relayConfig is what the TURN relay needs from the HTTP half.
type relayConfig struct {
	Realm string
	// Auth is the credential hook for server.Config.Auth: it verifies a TURN
	// username against the current clock and the ring of secrets and returns the
	// password (draft-uberti-behave-turn-rest-00 section 4.2).
	Auth func(username string) (password string, ok bool)
	// Options are the relay's listen addresses; TLSCertFile and TLSKeyFile
	// are the certificate for --turns-listen.
	Options                 relayOptions
	TLSCertFile, TLSKeyFile string
}

// ---- SEAM: TURN relay -------------------------------------------------------
// runRelay (relay.go) builds server.Server from
// server.Config{Realm: rc.Realm, Auth: rc.Auth}, serves it on the sockets
// named by the --stun-listen, --turn-tcp-listen and --turns-listen flags and
// returns a stop function. With none of them set no relay runs.
var startRelay = runRelay

// ---- end of seam ------------------------------------------------------------

// httpClient is the client for the issuer (discovery, keys, token endpoint).
// Nil is the default client; tests set it to trust a self-signed provider.
var httpClient *http.Client

// readSecretFile reads a secret: the file's content without surrounding
// whitespace. It refuses an empty file and one readable by everybody.
func readSecretFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("empty secret file path")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("%s: readable by everybody; chmod o-rwx it", path)
	}
	if fi.Size() > 4096 {
		return nil, fmt.Errorf("%s: too large for a secret", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 {
		return nil, fmt.Errorf("%s: empty", path)
	}
	return b, nil
}

func readSecrets(paths []string) ([][]byte, error) {
	var out [][]byte
	for _, p := range paths {
		b, err := readSecretFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func (c *config) validate() error {
	var missing []string
	for name, v := range map[string]string{"--issuer": c.Issuer, "--client-id": c.ClientID,
		"--client-secret-file": c.ClientSecretFile, "--public-url": c.PublicURL} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(c.SessionKeyFiles) == 0 {
		missing = append(missing, "--session-key-file")
	}
	if len(c.TurnSecretFiles) == 0 {
		missing = append(missing, "--turn-secret-file")
	}
	if len(c.Origins) == 0 {
		missing = append(missing, "--allowed-origin")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flag(s): %s", strings.Join(missing, ", "))
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("--tls-cert-file and --tls-key-file go together")
	}
	if err := c.Relay.validate(c.TLSCertFile, c.TLSKeyFile); err != nil {
		return err
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("--public-url must be an origin such as https://turn.example.org")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return errors.New("--public-url must be https (http only for a loopback host)")
	}
	for _, o := range c.Origins {
		ou, err := url.Parse(o)
		if o == "*" || err != nil || ou.Host == "" || (ou.Scheme != "https" && ou.Scheme != "http") || ou.Path != "" || ou.RawQuery != "" || o != ou.Scheme+"://"+ou.Host {
			return fmt.Errorf("--allowed-origin %q: want an exact origin such as https://go-tex.github.io", o)
		}
	}
	return nil
}

func isLoopback(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// app is the assembled daemon.
type app struct {
	Handler http.Handler
	ring    *creds.Keyring
	rv      *rendezvous.Server
	secure  bool
}

// newApp reads the secrets, discovers the issuer and builds the handlers.
func newApp(ctx context.Context, cfg config, logw io.Writer) (*app, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	logger := log.New(logw, "turnd: ", log.LstdFlags)
	cs, err := readSecretFile(cfg.ClientSecretFile)
	if err != nil {
		return nil, fmt.Errorf("client secret: %w", err)
	}
	skeys, err := readSecrets(cfg.SessionKeyFiles)
	if err != nil {
		return nil, fmt.Errorf("session key: %w", err)
	}
	tsecrets, err := readSecrets(cfg.TurnSecretFiles)
	if err != nil {
		return nil, fmt.Errorf("TURN secret: %w", err)
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	signer, err := session.NewSigner(ttl, skeys[0], skeys[1:]...)
	if err != nil {
		return nil, err
	}
	ring, err := creds.NewKeyring(tsecrets[0], tsecrets[1:]...)
	if err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	prov, err := rp.Discover(dctx, httpClient, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("issuer discovery: %w", err)
	}
	public := strings.TrimRight(cfg.PublicURL, "/")
	client, err := rp.NewClient(dctx, prov, rp.Config{ClientID: cfg.ClientID, Secret: string(cs), RedirectURI: public + "/callback"})
	if err != nil {
		return nil, fmt.Errorf("issuer keys: %w", err)
	}
	secure := strings.HasPrefix(public, "https://")
	login, err := session.NewLogin(session.LoginConfig{Client: client, Signer: signer, Origins: cfg.Origins, Secure: secure})
	if err != nil {
		return nil, err
	}
	auth := &session.Auth{Signer: signer, Logf: logger.Printf}
	if cfg.AccessTokenAudience != "" {
		auth.AccessTokens, err = oidc.New(dctx, oidc.Config{Issuer: cfg.Issuer, Audience: cfg.AccessTokenAudience,
			Type: "at+jwt", Client: httpClient})
		if err != nil {
			return nil, fmt.Errorf("access-token verifier: %w", err)
		}
	}
	rv, err := rendezvous.New(rendezvous.Config{Auth: auth.Subject, Keyring: ring, STUN: cfg.STUNURLs, TURN: cfg.TURNURLs,
		Origins: cfg.Origins, Limits: cfg.Limits, CredTTL: cfg.CredTTL})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	login.Mount(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.Handle("/", rv.Handler())
	return &app{Handler: limitBody(mux), ring: ring, rv: rv, secure: secure}, nil
}

// limitBody caps every request body: no endpoint reads more than a message.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		next.ServeHTTP(w, r)
	})
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// The event stream extends its own write deadline per write.
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
}
