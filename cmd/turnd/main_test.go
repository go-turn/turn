package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-turn/turn/creds"
	"github.com/go-turn/turn/internal/fakeidp"
	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	"github.com/go-turn/turn/rendezvous/client"
	wstransport "github.com/grpc-transports/websocket"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const origin = "https://go-tex.github.io"

var (
	turnSecret = "turn-secret-0123456789abcdef"
	sessionKey = "session-key-0123456789abcdef0123456789"
)

func writeSecret(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type daemon struct {
	base string
	idp  *fakeidp.IdP
	out  *bytes.Buffer
	errs *bytes.Buffer
}

// run starts turnd through RootCmd against a fake provider and stops it at the end of the test.
func run(t *testing.T, extra ...string) *daemon {
	t.Helper()
	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	idp := fakeidp.New(t, "turnd", "client-s3cret", base+"/callback")
	httpClient = idp.Client()
	t.Cleanup(func() { httpClient = nil })
	args := []string{"--issuer", idp.Issuer, "--client-id", "turnd",
		"--client-secret-file", writeSecret(t, "cs", "client-s3cret", 0o600),
		"--session-key-file", writeSecret(t, "sk", sessionKey, 0o600),
		"--turn-secret-file", writeSecret(t, "ts", turnSecret, 0o600),
		"--allowed-origin", origin, "--public-url", base, "--listen", fmt.Sprintf("127.0.0.1:%d", port),
		"--access-token-audience", "turnd-api",
		"--stun-uri", "stun:turn.example:3478", "--turn-uri", "turn:turn.example:3478?transport=udp"}
	args = append(args, extra...)
	ready := make(chan string, 1)
	readyHook = func(a string) { ready <- a }
	t.Cleanup(func() { readyHook = nil })
	d := &daemon{base: base, idp: idp, out: &bytes.Buffer{}, errs: &bytes.Buffer{}}
	cmd := RootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(d.out)
	cmd.SetErr(d.errs)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()
	select {
	case <-ready:
	case err := <-done:
		cancel()
		t.Fatalf("turnd exited: %v\n%s", err, d.errs)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("turnd did not start")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shutdown: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("turnd did not stop")
		}
	})
	return d
}

var pageRe = regexp.MustCompile(`var msg = (\{.*\}), target = ("[^"]*");`)

// login drives the popup like a browser and returns the session token the page would postMessage.
func (d *daemon) login(t *testing.T) (token, target string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := *d.idp.Client()
	c.Jar = jar
	resp, err := c.Get(d.base + "/login?origin=" + url.QueryEscape(origin))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	m := pageRe.FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("no postMessage page (%d):\n%s", resp.StatusCode, b)
	}
	var msg struct{ Type, Token string }
	_ = json.Unmarshal([]byte(m[1]), &msg)
	_ = json.Unmarshal([]byte(m[2]), &target)
	if msg.Type != "turnd-session" {
		t.Fatalf("%s", m[1])
	}
	return msg.Token, target
}

// get is a plain HTTP GET: the only HTTP left besides the WebSocket is /login,
// /callback and /healthz.
func (d *daemon) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(d.base + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// dial opens the gRPC WebSocket as a browser of the given origin would ("" is a native client).
func (d *daemon) dial(t *testing.T, origin string) turnv1.TurndClient {
	t.Helper()
	cfg := wstransport.ClientConfig{}
	if origin != "" {
		cfg.HTTPHeader = http.Header{"Origin": {origin}}
	}
	cc, err := client.Dial(d.base, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	return turnv1.NewTurndClient(cc)
}

func rctx(t *testing.T, token string) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	if token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func TestEndToEnd(t *testing.T) {
	var relay relayConfig
	old := startRelay
	startRelay = func(_ context.Context, rc relayConfig) (func(), error) { relay = rc; return func() {}, nil }
	t.Cleanup(func() { startRelay = old })

	d := run(t)
	if !strings.Contains(d.out.String(), "listening on 127.0.0.1:") {
		t.Fatalf("stdout %q", d.out)
	}
	token, target := d.login(t)
	if target != origin {
		t.Fatalf("target %q", target)
	}
	// the session token opens a room; a guest knocks, the host admits it, they
	// exchange a message and the guest gets credentials: all over the WebSocket.
	rpc := d.dial(t, origin)
	room, err := rpc.CreateRoom(rctx(t, token), &turnv1.CreateRoomRequest{})
	if err != nil || len(room.Room) != 32 {
		t.Fatalf("create %v %v", room, err)
	}
	hctx := metadata.AppendToOutgoingContext(rctx(t, room.Token), "x-turn-room", room.Room)
	hs, err := rpc.Room(hctx)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := rpc.JoinRoom(rctx(t, ""), &turnv1.JoinRoomRequest{Room: room.Room, Name: "Bob"})
	if err != nil || !guest.Pending {
		t.Fatalf("join %v %v", guest, err)
	}
	// pending: no credentials yet
	if _, err := rpc.RoomCredentials(rctx(t, guest.Token), &turnv1.RoomRef{Room: room.Room}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a pending guest got credentials: %v", err)
	}
	if e, err := hs.Recv(); err != nil || e.Kind != "sys.knock" || string(e.Body) != "Bob" {
		t.Fatalf("%v %v", e, err)
	}
	if _, err := rpc.Admit(rctx(t, room.Token), &turnv1.DecideRequest{Room: room.Room, Peer: guest.Peer}); err != nil {
		t.Fatal(err)
	}
	gctx := metadata.AppendToOutgoingContext(rctx(t, guest.Token), "x-turn-room", room.Room)
	gs, err := rpc.Room(gctx)
	if err != nil {
		t.Fatal(err)
	}
	if e, err := gs.Recv(); err != nil || e.Kind != "sys.admitted" {
		t.Fatalf("%v %v", e, err)
	}
	if err := gs.Send(&turnv1.Envelope{From: guest.Peer, To: "host", Kind: "answer", Body: []byte("sdp")}); err != nil {
		t.Fatal(err)
	}
	for {
		e, err := hs.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind == "answer" {
			if string(e.Body) != "sdp" {
				t.Fatalf("%v", e)
			}
			break
		}
	}
	cr, err := rpc.RoomCredentials(rctx(t, guest.Token), &turnv1.RoomRef{Room: room.Room})
	if err != nil || len(cr.IceServers) != 2 {
		t.Fatalf("guest credentials %v %v", cr, err)
	}
	turn := cr.IceServers[1]
	if turn.Urls[0] != "turn:turn.example:3478?transport=udp" {
		t.Fatalf("%+v", turn)
	}
	// the relay seam receives a hook that accepts exactly what was minted
	if relay.Auth == nil || relay.Realm != "127.0.0.1" {
		t.Fatalf("seam not wired: %+v", relay)
	}
	if pw, ok := relay.Auth(turn.Username); !ok || pw != turn.Credential {
		t.Fatalf("relay Auth(%q) = %q, %v", turn.Username, pw, ok)
	}
	if _, ok := relay.Auth("1:forged"); ok {
		t.Fatal("relay Auth accepted a forged username")
	}
	ring, _ := creds.NewKeyring([]byte(turnSecret))
	if pw, ok := ring.Verify(turn.Username, time.Now()); !ok || pw != turn.Credential {
		t.Fatal("credentials do not verify under the configured secret")
	}
	// the host's subject, not a name, is in the username
	if strings.Contains(turn.Username, "alice") {
		t.Fatalf("username leaks the name: %q", turn.Username)
	}
	// an issuer access token works on the API, an ID token does not
	native := d.dial(t, "") // no Origin header: a native client
	if _, err := native.Credentials(rctx(t, d.idp.AccessToken("turnd-api")), &turnv1.CredentialsRequest{}); err != nil {
		t.Fatalf("access token: %v", err)
	}
	if _, err := native.Credentials(rctx(t, d.idp.IDToken("turnd-api")), &turnv1.CredentialsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("ID token taken for an access token: %v", err)
	}
	if _, err := native.Credentials(rctx(t, ""), &turnv1.CredentialsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no token: %v", err)
	}
	// the exact origin is enforced at the WebSocket upgrade: a foreign origin, or
	// the right host on another scheme, never gets a connection
	for _, o := range []string{"https://evil.example", "http://go-tex.github.io", "https://go-tex.github.io:8443", "null"} {
		if _, err := d.dial(t, o).Credentials(rctx(t, token), &turnv1.CredentialsRequest{}); status.Code(err) != codes.Unavailable {
			t.Errorf("origin %q: %v", o, err)
		}
	}
	if _, err := d.dial(t, origin).Credentials(rctx(t, token), &turnv1.CredentialsRequest{}); err != nil {
		t.Fatalf("control, the allowed origin: %v", err)
	}
	// the REST API is gone
	for _, p := range []string{"/rooms", "/credentials", "/rooms/x/events"} {
		if st, _ := d.get(t, p); st != 404 && st != 405 {
			t.Errorf("GET %s: %d", p, st)
		}
	}
	jar, _ := cookiejar.New(nil)
	c := *d.idp.Client()
	c.Jar, c.CheckRedirect = jar, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Get(d.base + "/login?origin=https://evil.example")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
		t.Fatalf("open redirect at /login: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// the client secret is in no URL
	resp, _ = c.Get(d.base + "/login?origin=" + url.QueryEscape(origin))
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "client-s3cret") || strings.Contains(loc, "client_secret") {
		t.Fatalf("secret in the authorization URL: %s", loc)
	}
	// health
	if st, b := d.get(t, "/healthz"); st != 200 || b != "ok\n" {
		t.Fatalf("healthz %d %q", st, b)
	}
	// an oversized message is refused by the server's receive bound
	if err := gs.Send(&turnv1.Envelope{From: guest.Peer, To: "host", Kind: "x", Body: make([]byte, 1<<20)}); err != nil {
		t.Logf("send: %v", err) // the stream may already be refusing
	}
	for {
		if _, err := gs.Recv(); err != nil {
			if status.Code(err) != codes.ResourceExhausted {
				t.Fatalf("1 MiB message: %v", err)
			}
			break
		}
	}
}

func TestRotatedSecretsStillVerify(t *testing.T) {
	var relay relayConfig
	old := startRelay
	startRelay = func(_ context.Context, rc relayConfig) (func(), error) { relay = rc; return func() {}, nil }
	t.Cleanup(func() { startRelay = old })
	prev := "previous-secret-0123456789ab"
	prevRing, _ := creds.NewKeyring([]byte(prev))
	user, pass := prevRing.Mint("u1", time.Now().Add(time.Hour))
	run(t, "--turn-secret-file", writeSecret(t, "ts2", prev, 0o600))
	if pw, ok := relay.Auth(user); !ok || pw != pass {
		t.Fatalf("a username signed by the previous secret is refused: %q %v", pw, ok)
	}
}

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := RootCmd()
	var out bytes.Buffer
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	return out.String(), err
}

func TestFlagValidation(t *testing.T) {
	good := writeSecret(t, "s", "0123456789abcdef0123456789abcdef", 0o600)
	base := []string{"--issuer", "https://idp.example", "--client-id", "c", "--client-secret-file", good,
		"--session-key-file", good, "--turn-secret-file", good, "--allowed-origin", origin, "--public-url", "https://turn.example"}
	with := func(over ...string) []string { return append(append([]string(nil), base...), over...) }
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"nothing":          {nil, "missing required flag"},
		"wildcard origin":  {with("--allowed-origin", "*"), "exact origin"},
		"origin with path": {with("--allowed-origin", "https://a.example/x"), "exact origin"},
		"http public url":  {append(base[:len(base)-1:len(base)-1], "http://turn.example"), "https"},
		"tls half":         {with("--tls-cert-file", "x"), "go together"},
		"positional":       {with("extra"), "unknown command"},
		"unknown flag":     {with("--client-secret", "hunter2"), "unknown flag"},
	} {
		out, err := execute(t, c.args...)
		if err == nil || !strings.Contains(err.Error()+out, c.want) {
			t.Errorf("%s: err=%v out=%q, want %q", name, err, out, c.want)
		}
		if strings.Contains(out, "hunter2") && name != "unknown flag" {
			t.Errorf("%s: echoed a secret", name)
		}
	}
	// there is no flag that takes a secret's value, and none reads the environment
	out, _ := execute(t, "--help")
	for _, bad := range []string{"--client-secret ", "--session-key ", "--turn-secret "} {
		if strings.Contains(out, bad) {
			t.Errorf("help offers %q", bad)
		}
	}
}

func TestSecretFileRules(t *testing.T) {
	if runtime.GOOS != "windows" {
		if _, err := readSecretFile(writeSecret(t, "open", "0123456789abcdef", 0o644)); err == nil || !strings.Contains(err.Error(), "readable by everybody") {
			t.Errorf("world-readable secret: %v", err)
		}
	}
	for name, p := range map[string]string{"empty": writeSecret(t, "e", "   ", 0o600), "missing": "/nonexistent/x", "dir": t.TempDir(), "blank path": ""} {
		if _, err := readSecretFile(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if b, err := readSecretFile(writeSecret(t, "ok", "  secret-value \n", 0o600)); err != nil || string(b) != "secret-value" {
		t.Errorf("%q %v", b, err)
	}
	big := writeSecret(t, "big", strings.Repeat("a", 5000), 0o600)
	if _, err := readSecretFile(big); err == nil {
		t.Error("oversized secret file accepted")
	}
	// a short key is refused at startup, not used
	short := writeSecret(t, "short", "tooshort", 0o600)
	good := writeSecret(t, "good", "0123456789abcdef0123456789abcdef", 0o600)
	_, err := execute(t, "--issuer", "https://x.example", "--client-id", "c", "--client-secret-file", good, "--session-key-file", short,
		"--turn-secret-file", good, "--allowed-origin", origin, "--public-url", "https://turn.example")
	if err == nil || !strings.Contains(err.Error(), "shorter") {
		t.Errorf("short session key: %v", err)
	}
}

func TestVersionAndExit(t *testing.T) {
	out, err := execute(t, "--version")
	if err != nil || !strings.Contains(out, "turnd version") {
		t.Fatalf("%q %v", out, err)
	}
	code := -1
	oldExit := osExit
	osExit = func(c int) { code = c }
	defer func() { osExit = oldExit }()
	os.Args = []string{"turnd", "--nope"}
	main()
	if code != 1 {
		t.Fatalf("exit code %d", code)
	}
}
