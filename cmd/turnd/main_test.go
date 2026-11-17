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

func (d *daemon) do(t *testing.T, method, path, token string, body any, hdr ...string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	r, _ := http.NewRequest(method, d.base+path, rd)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
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
	// the session token opens a room and mints credentials
	st, b := d.do(t, "POST", "/rooms", token, nil, "Origin", origin)
	var room struct {
		Room, Token string
	}
	if st != 201 || json.Unmarshal(b, &room) != nil || len(room.Room) != 32 {
		t.Fatalf("create %d %s", st, b)
	}
	st, b = d.do(t, "POST", "/rooms/"+room.Room+"/join", "", nil, "Origin", origin)
	var guest struct{ Peer, Token string }
	if st != 201 || json.Unmarshal(b, &guest) != nil {
		t.Fatalf("join %d %s", st, b)
	}
	if st, b := d.do(t, "POST", "/rooms/"+room.Room+"/messages", guest.Token,
		map[string]string{"from": guest.Peer, "to": "host", "kind": "answer", "body": "sdp"}); st != 204 {
		t.Fatalf("message %d %s", st, b)
	}
	st, b = d.do(t, "POST", "/rooms/"+room.Room+"/credentials", guest.Token, nil)
	var cr creds.Response
	if st != 200 || json.Unmarshal(b, &cr) != nil || len(cr.ICEServers) != 2 {
		t.Fatalf("guest credentials %d %s", st, b)
	}
	turn := cr.ICEServers[1]
	if turn.URLs[0] != "turn:turn.example:3478?transport=udp" {
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
	if st, b := d.do(t, "POST", "/credentials", d.idp.AccessToken("turnd-api"), nil); st != 200 {
		t.Fatalf("access token: %d %s", st, b)
	}
	if st, _ := d.do(t, "POST", "/credentials", d.idp.IDToken("turnd-api"), nil); st != 401 {
		t.Fatalf("ID token taken for an access token: %d", st)
	}
	if st, _ := d.do(t, "POST", "/credentials", "", nil); st != 401 {
		t.Fatalf("no token: %d", st)
	}
	// a foreign origin is refused; so is a foreign login origin
	if st, _ := d.do(t, "POST", "/rooms", token, nil, "Origin", "https://evil.example"); st != 403 {
		t.Fatalf("foreign origin: %d", st)
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
	if st, b := d.do(t, "GET", "/healthz", "", nil); st != 200 || string(b) != "ok\n" {
		t.Fatalf("healthz %d %q", st, b)
	}
	// an oversized body is refused by the cap, not read
	big := strings.Repeat("a", 1<<20)
	if st, _ := d.do(t, "POST", "/rooms/"+room.Room+"/messages", guest.Token, map[string]string{"from": guest.Peer, "to": "host", "kind": "x", "body": big}); st != 413 {
		t.Fatalf("1 MiB body: %d", st)
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
