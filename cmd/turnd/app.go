package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/go-authn/oidc"
	"github.com/go-authn/rp"
	"github.com/go-turn/turn/creds"
	"github.com/go-turn/turn/rendezvous"
	"github.com/go-turn/turn/session"
	wstransport "github.com/grpc-transports/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
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
	// RenewalLifetime is how long a login can be renewed (bridge's
	// refresh_lifetime for this client); zero turns renewal off.
	RenewalLifetime time.Duration
	Limits          rendezvous.Limits
	Relay           relayOptions
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
	gs      *grpc.Server
	lis     net.Listener
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
	scopes := []string{"openid"}
	if cfg.RenewalLifetime > 0 {
		scopes = append(scopes, "offline_access") // a refresh token, kept server side
	}
	client, err := rp.NewClient(dctx, prov, rp.Config{ClientID: cfg.ClientID, Secret: string(cs), RedirectURI: public + "/callback", Scopes: scopes})
	if err != nil {
		return nil, fmt.Errorf("issuer keys: %w", err)
	}
	var renewer *session.Renewer
	if cfg.RenewalLifetime > 0 {
		if renewer, err = session.NewRenewer(session.RenewConfig{Refresher: client, Signer: signer, Lifetime: cfg.RenewalLifetime, Logf: logger.Printf}); err != nil {
			return nil, err
		}
	}
	secure := strings.HasPrefix(public, "https://")
	login, err := session.NewLogin(session.LoginConfig{Client: client, Signer: signer, Origins: cfg.Origins, Secure: secure, Renewer: renewer, Logf: logger.Printf})
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
	var renew func(context.Context, string) (string, time.Time, error)
	if renewer != nil {
		renew = func(ctx context.Context, tok string) (string, time.Time, error) {
			t, exp, err := renewer.Renew(ctx, tok)
			switch {
			case errors.Is(err, session.ErrEnded):
				err = rendezvous.ErrSessionEnded
			case errors.Is(err, session.ErrUnavailable):
				err = rendezvous.ErrSessionUnavailable
			}
			return t, exp, err
		}
	}
	rv, err := rendezvous.New(rendezvous.Config{Auth: auth.Authenticate, Renew: renew, Keyring: ring, STUN: cfg.STUNURLs, TURN: cfg.TURNURLs,
		Limits: cfg.Limits, CredTTL: cfg.CredTTL})
	if err != nil {
		return nil, err
	}

	// gRPC over a WebSocket: browsers cannot speak anything else.
	h, lis := wstransport.HandlerListener(wstransport.ServerConfig{
		Path:           GRPCPath,
		OriginPatterns: originHosts(cfg.Origins),
		OnUpgrade: func(r *http.Request) (any, error) {
			// The exact origin, scheme and port included (the library's patterns
			// match the host only). No Origin header is a native client.
			if o := r.Header.Get("Origin"); o != "" && !slices.Contains(cfg.Origins, o) {
				return nil, &wstransport.UpgradeError{Code: http.StatusForbidden, Message: "origin not allowed"}
			}
			return nil, nil
		},
		Logger: logger,
	})
	gs := grpc.NewServer(
		grpc.Creds(wstransport.ServerCredentials()),
		grpc.MaxRecvMsgSize(rv.MaxRecvMsgSize()),
		grpc.MaxConcurrentStreams(32),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: time.Minute, Timeout: 20 * time.Second}),
	)
	rv.Register(gs)
	go func() { _ = gs.Serve(lis) }()

	mux := http.NewServeMux()
	login.Mount(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.Handle(GRPCPath, h)
	return &app{Handler: mux, ring: ring, rv: rv, secure: secure, gs: gs, lis: lis}, nil
}

// GRPCPath is where the gRPC WebSocket is served.
const GRPCPath = "/grpc"

// originHosts is the host part of each allowed origin, for the WebSocket
// library's pattern check; OnUpgrade then compares the whole origin.
func originHosts(origins []string) []string {
	var hosts []string
	for _, o := range origins {
		if u, err := url.Parse(o); err == nil && u.Host != "" {
			hosts = append(hosts, u.Host)
		}
	}
	return hosts
}

// Close stops the gRPC server.
func (a *app) Close() {
	a.gs.Stop()
	_ = a.lis.Close()
}

// newHTTPServer has no Read/WriteTimeout: they would cut the long-lived gRPC
// WebSocket, and every other endpoint is a bodyless GET answered at once.
// Slow headers are bounded by ReadHeaderTimeout, idle connections by IdleTimeout.
func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}
