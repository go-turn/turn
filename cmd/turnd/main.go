// Command turnd serves go-turn: the OpenID Connect login, ephemeral TURN
// credentials, the rendezvous, and (with the relay flags) the STUN/TURN relay
// at the marked seam in app.go.
//
// Every secret is read from a file; none is accepted as a flag value or from
// the environment.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-turn/turn/server"
	"github.com/go-turn/turn/telemetry"
	"github.com/spf13/cobra"
)

// version is set at build time (-ldflags "-X main.version=v0.1.0").
var version = "dev"

// osExit is replaceable by tests.
var osExit = os.Exit

func main() {
	if err := RootCmd().Execute(); err != nil {
		osExit(1)
	}
}

// RootCmd builds the command. Tests drive it with SetArgs, SetOut and SetErr.
func RootCmd() *cobra.Command {
	var cfg config
	var ready func(addr string) // test hook: called with the bound address
	cmd := &cobra.Command{
		Use:           "turnd",
		Short:         "TURN credentials, OIDC login and rendezvous for WebRTC peers",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer stop()
			return serve(ctx, cmd, cfg, ready)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.Issuer, "issuer", "", "OpenID Connect issuer URL (https)")
	f.StringVar(&cfg.ClientID, "client-id", "", "OAuth client ID registered at the issuer")
	f.StringVar(&cfg.ClientSecretFile, "client-secret-file", "", "file holding the OAuth client secret")
	f.StringVar(&cfg.AccessTokenAudience, "access-token-audience", "", "accept issuer access tokens (at+jwt) for this audience on the API (off when empty)")
	f.StringArrayVar(&cfg.SessionKeyFiles, "session-key-file", nil, "file holding a session-token HMAC key of 32+ bytes; the first signs, the others only verify (repeat to rotate)")
	f.StringArrayVar(&cfg.TurnSecretFiles, "turn-secret-file", nil, "file holding a TURN REST HMAC secret of 16+ bytes; the first mints, the others only verify (repeat to rotate)")
	f.StringArrayVar(&cfg.Origins, "allowed-origin", nil, "exact origin allowed to log in and call the API, e.g. https://go-tex.github.io (repeat)")
	f.StringVar(&cfg.PublicURL, "public-url", "", "public origin of this server, e.g. https://turn.example.org (the OIDC redirect URI is <public-url>/callback)")
	f.StringVar(&cfg.Listen, "listen", "127.0.0.1:8080", "HTTP listen address")
	f.StringVar(&cfg.TLSCertFile, "tls-cert-file", "", "serve HTTPS with this certificate (else plain HTTP behind a TLS proxy)")
	f.StringVar(&cfg.TLSKeyFile, "tls-key-file", "", "private key for --tls-cert-file")
	f.StringVar(&cfg.Realm, "realm", "", "TURN realm (default: the public URL's host)")
	f.StringArrayVar(&cfg.STUNURLs, "stun-uri", nil, "STUN URL advertised to clients, e.g. stun:turn.example.org:3478 (repeat)")
	f.StringArrayVar(&cfg.TURNURLs, "turn-uri", nil, "TURN URL advertised to clients, e.g. turns:turn.example.org:443?transport=tcp (repeat)")
	f.StringVar(&cfg.Relay.RelayIP, "relay-ip", "", "address relayed UDP sockets bind to (required with a relay listen flag)")
	f.StringVar(&cfg.Relay.RelayAdvertiseIP, "relay-advertise-ip", "", "address reported to clients as the relayed address when it differs from --relay-ip")
	f.StringVar(&cfg.Relay.STUNListen, "stun-listen", "", "serve STUN and TURN over UDP here, e.g. :3478 (relay off when no relay listen flag is set)")
	f.StringVar(&cfg.Relay.TURNTCPListen, "turn-tcp-listen", "", "serve TURN over TCP here, e.g. :3478")
	f.StringVar(&cfg.Relay.TURNSListen, "turns-listen", "", "serve TURN over TLS here, e.g. :443 (uses --tls-cert-file and --tls-key-file)")
	f.StringArrayVar(&cfg.Relay.ProxyFrom, "proxy-protocol-from", nil, "accept a PROXY protocol v2 (or v1) header on TCP and TLS connections from this prefix, e.g. 127.0.0.1/32 for Caddy on the same host (repeat; off when empty; never UDP)")
	f.DurationVar(&cfg.Relay.MaxAllocationAge, "max-allocation-age", 12*time.Hour, "longest an allocation may live: a call outlasts the 1 h credential that opened it (Refresh, permissions and channels keep working with its expired username), but Refresh is refused past this age")
	f.UintVar(&cfg.Relay.PortMin, "relay-port-min", 0, "lowest relayed UDP port (0 with --relay-port-max 0: any)")
	f.UintVar(&cfg.Relay.PortMax, "relay-port-max", 0, "highest relayed UDP port")
	f.DurationVar(&cfg.SessionTTL, "session-ttl", time.Hour, "lifetime of a session token")
	f.DurationVar(&cfg.RenewalLifetime, "session-renewal-lifetime", 168*time.Hour, "how long a login can be renewed (RenewSession): set it to the client's refresh_lifetime at bridge; the refresh token is kept in memory, server side, and a restart ends every renewal (0 turns renewal off)")
	f.DurationVar(&cfg.CredTTL, "cred-ttl", time.Hour, "lifetime of host TURN credentials (a guest's never outlive the room)")
	f.DurationVar(&cfg.Limits.RoomTTL, "room-ttl", time.Hour, "lifetime of a room")
	f.DurationVar(&cfg.Limits.HostGrace, "host-grace", 2*time.Minute, "how long a room outlives its host's stream: the host back within it keeps the role, after it the earliest-admitted guest becomes the host (negative: the host leaving closes the room)")
	f.IntVar(&cfg.Limits.MaxMessageBytes, "max-message-bytes", 16<<10, "largest message body")
	f.IntVar(&cfg.Limits.MaxQueue, "max-queue", 64, "events queued per peer")
	f.IntVar(&cfg.Limits.MaxGuests, "max-guests", 8, "guests per room")
	f.IntVar(&cfg.Limits.MaxRoomsPerSubject, "max-rooms-per-subject", 4, "live rooms per person")
	f.IntVar(&cfg.Limits.MaxRooms, "max-rooms", 1024, "live rooms on the server")
	cfg.Otel = telemetry.DefaultConfig()
	f.StringVar(&cfg.Otel.Endpoint, "otel-endpoint", "", "OpenTelemetry collector: https://host:4318 for http, host:4317 for grpc (telemetry off when empty)")
	f.StringVar(&cfg.Otel.Protocol, "otel-protocol", "http", "OTLP transport: grpc or http")
	f.StringVar(&cfg.OtelTokenFile, "otel-token-file", "", "file holding the collector's bearer token (never read from the environment: OTEL_EXPORTER_OTLP_HEADERS is ignored)")
	f.BoolVar(&cfg.Otel.Insecure, "otel-insecure", false, "allow http:// or plaintext gRPC to the collector (a token is then refused unless the collector is on loopback)")
	f.Float64Var(&cfg.Otel.SampleRatio, "otel-sample-ratio", 1, "fraction of traces kept, 0..1")
	f.StringVar(&cfg.Otel.ServiceName, "otel-service-name", "turnd", "service.name of the exported telemetry")
	f.BoolVar(&cfg.Otel.TrustClientContext, "otel-trust-client-context", false, "continue a caller's W3C traceparent (off: every request starts its own trace)")
	// the test hook is reached through a package variable set before Execute.
	ready = readyHook
	cmd.AddCommand(mintCmd())
	return cmd
}

// readyHook is set by tests to learn the bound address.
var readyHook func(addr string)

func serve(ctx context.Context, cmd *cobra.Command, cfg config, ready func(string)) error {
	out := cmd.OutOrStdout()
	if cfg.Realm == "" {
		// validate runs in newApp; a bad public URL is reported there.
		cfg.Realm = hostOf(cfg.PublicURL)
	}
	tel, logger, err := setupTelemetry(ctx, &cfg, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tel.Shutdown(sctx); err != nil {
			logger.Warn("telemetry shutdown", "err", err)
		}
	}()
	a, err := newApp(ctx, cfg, logger, tel)
	if err != nil {
		return err
	}
	defer a.Close()
	rc := relayConfig{Realm: cfg.Realm, Auth: a.ring.Auth(nil), AuthExisting: a.ring.AuthExisting(),
		Options: cfg.Relay, TLSCertFile: cfg.TLSCertFile, TLSKeyFile: cfg.TLSKeyFile, Logger: logger}
	if tel.Enabled() {
		m := tel.Metrics()
		rc.Observer = m.ServerObserver()
		rc.OnServer = func(s *server.Server) { m.BindRelay(s.Stats, s.Usage) }
	}
	stopRelay, err := startRelay(ctx, rc)
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}
	defer stopRelay()
	go a.rv.Run(ctx, 30*time.Second)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	srv := newHTTPServer(cfg.Listen, tel.HTTP(a.Handler, GRPCPath))
	fmt.Fprintf(out, "turnd %s listening on %s\n", version, ln.Addr())
	if ready != nil {
		ready(ln.Addr().String())
	}
	errc := make(chan error, 1)
	go func() {
		if cfg.TLSCertFile != "" {
			errc <- srv.ServeTLS(ln, cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		_ = srv.Close()
	}
	return nil
}

func hostOf(publicURL string) string {
	u, err := url.Parse(publicURL)
	if err != nil || u.Hostname() == "" {
		return publicURL
	}
	return u.Hostname()
}
