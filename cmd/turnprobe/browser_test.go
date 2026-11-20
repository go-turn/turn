//go:build !js

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseCandidate(t *testing.T) {
	good := []struct {
		line, typ, proto, addr, port string
	}{
		{"candidate:842163049 1 udp 41885439 203.0.113.7 54321 typ relay raddr 0.0.0.0 rport 0 generation 0 ufrag x network-cost 999", "relay", "udp", "203.0.113.7", "54321"},
		{"a=candidate:1 1 UDP 2122260223 192.0.2.1 5000 typ host", "host", "udp", "192.0.2.1", "5000"},
		{"candidate:3 1 udp 1686052607 198.51.100.2 40000 typ srflx raddr 10.0.0.2 rport 40000", "srflx", "udp", "198.51.100.2", "40000"},
		{"candidate:4 1 udp 41885439 2001:db8::1 3000 typ relay raddr :: rport 0", "relay", "udp", "2001:db8::1", "3000"},
	}
	for _, g := range good {
		c, err := parseCandidate(g.line)
		if err != nil {
			t.Fatalf("%q: %v", g.line, err)
		}
		if c.Type != g.typ || c.Protocol != g.proto || c.Address != g.addr || c.Port != g.port {
			t.Errorf("%q parsed as %+v", g.line, c)
		}
	}
	for _, bad := range []string{"", "candidate:1 1 udp 1 1.2.3.4 5 relay", "candidate:1 1 udp 1 1.2.3.4 typ relay", "foo bar", "candidate:1 1 udp 1 1.2.3.4 5 typ"} {
		if _, err := parseCandidate(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestJudge(t *testing.T) {
	relay := "candidate:1 1 udp 41885439 203.0.113.7 54321 typ relay raddr 0.0.0.0 rport 0"
	host := "candidate:2 1 udp 2122260223 192.0.2.1 5000 typ host"
	cases := []struct {
		name     string
		g        gathered
		pass     bool
		relays   int
		other    int
		unparsed int
	}{
		{"empty", gathered{State: "complete"}, false, 0, 0, 0},
		{"host only", gathered{Candidates: []string{host}}, false, 0, 1, 0},
		{"relay", gathered{Candidates: []string{host, relay}}, true, 1, 1, 0},
		{"garbage is counted, not a pass", gathered{Candidates: []string{"typ relay"}}, false, 0, 0, 1},
		{"errors alone", gathered{Errors: []iceError{{Code: 701, Text: "x"}}}, false, 0, 0, 0},
	}
	for _, c := range cases {
		v := judge(c.g)
		if v.Pass != c.pass || len(v.Relays) != c.relays || v.Other != c.other || v.Unparsed != c.unparsed {
			t.Errorf("%s: %+v", c.name, v)
		}
	}
}

func TestVerdictLine(t *testing.T) {
	pass := judge(gathered{Candidates: []string{"candidate:1 1 udp 41885439 203.0.113.7 54321 typ relay"}})
	if got, want := pass.line("turns:h:443?transport=tcp", "Chrome/1"), "PASS turns:h:443?transport=tcp relay=udp/203.0.113.7:54321 chrome=Chrome/1"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
	fail := judge(gathered{State: "complete", Errors: []iceError{{URL: "turns:h:443", Code: 701, Text: "TURN host lookup failed"}}})
	l := fail.line("turns:h:443?transport=tcp", "Chrome/1")
	for _, w := range []string{"FAIL ", "gathering=complete", "701", "TURN host lookup failed", "chrome=Chrome/1"} {
		if !strings.Contains(l, w) {
			t.Errorf("%q lacks %q", l, w)
		}
	}
}

func TestPageScriptCarriesCredentialInTheScriptOnly(t *testing.T) {
	s, err := pageScript(pageConfig{URLs: []string{"turns:h:443?transport=tcp"}, Username: "u", Credential: `p"w</script>`, TimeoutMs: 5})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "\"credential\":\"p\\\"w\\u003c/script\\u003e\"") {
		t.Errorf("credential not JSON-escaped in %s", s)
	}
	if !strings.Contains(s, `iceTransportPolicy: "relay"`) {
		t.Error("the page must force relay-only")
	}
}

func TestSummarizeALPN(t *testing.T) {
	if got := summarizeALPN(nil); !strings.Contains(got, "not measured") {
		t.Errorf("no hello must read as not measured, got %q", got)
	}
	got := summarizeALPN([]helloRecord{{ALPN: []string{"stun.turn"}}, {ALPN: []string{"stun.turn"}}, {}})
	if !strings.Contains(got, "3 ClientHello") || !strings.Contains(got, "[stun.turn]") || !strings.Contains(got, "<no ALPN extension>") {
		t.Errorf("got %q", got)
	}
}

func TestHelloListenerLogsALPN(t *testing.T) {
	log := &helloLog{}
	addr, stop, err := helloListener(log)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for _, protos := range [][]string{{"stun.turn", "h2"}, nil} {
		c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: protos, ServerName: "turn.example"})
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	h := log.all()
	if len(h) != 2 || strings.Join(h[0].ALPN, ",") != "stun.turn,h2" || h[0].ServerName != "turn.example" || len(h[1].ALPN) != 0 {
		t.Errorf("hellos: %+v", h)
	}
}

func runCLI(args ...string) (string, error) {
	var out bytes.Buffer
	cmd := RootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	return out.String(), err
}

func TestBrowserFlags(t *testing.T) {
	if _, err := runCLI("--alpn", "--server", "turn:h"); err == nil || !strings.Contains(err.Error(), "--alpn needs --browser") {
		t.Errorf("err = %v", err)
	}
	// --realm is not needed in browser mode, the others are.
	_, err := runCLI("--browser")
	if err == nil || !strings.Contains(err.Error(), "--server, --username, --password-file") || strings.Contains(err.Error(), "--realm") {
		t.Errorf("err = %v", err)
	}
}

func TestBrowserModeRefusals(t *testing.T) {
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--browser", "--username", "u", "--password-file", pw}
	if _, err := runCLI(append(base, "--server", "turns:h:443?transport=tcp", "--timeout", "0s")...); err == nil || !strings.Contains(err.Error(), "--timeout must be positive") {
		t.Errorf("timeout 0: %v", err)
	}
	if _, err := runCLI(append(base, "--server", "http://h")...); err == nil || !strings.Contains(err.Error(), "--server") {
		t.Errorf("bad server: %v", err)
	}
	if _, err := runCLI("--browser", "--username", "u", "--password-file", pw+".missing", "--server", "turn:h"); err == nil || !strings.Contains(err.Error(), "--password-file") {
		t.Errorf("missing password file: %v", err)
	}
}

// A Chrome that cannot start is a FAIL line and a non-zero exit, never a pass,
// and the ALPN measurement says its run failed instead of reporting "none".
func TestBrowserUnstartableChromeFails(t *testing.T) {
	targets := []target{{Raw: "turns:h:443?transport=tcp", Scheme: "turns", Host: "h", Port: "443", Transport: "tcp"}}
	var out bytes.Buffer
	err := runBrowser(context.Background(), &out, browserRun{
		Targets: targets, Username: "u", Password: "p", ALPN: true,
		Opts: browserOptions{ChromePath: filepath.Join(t.TempDir(), "no-such-chrome"), Timeout: time.Second},
	})
	if err == nil || !strings.Contains(err.Error(), "1 of 1 servers failed") {
		t.Errorf("err = %v", err)
	}
	s := out.String()
	if !strings.HasPrefix(s, "FAIL turns:h:443?transport=tcp") || !strings.Contains(s, "ALPN listener=") || !strings.Contains(s, "chrome run failed") {
		t.Errorf("output:\n%s", s)
	}
}

var errFake = errors.New("fake failure")

func TestPageScriptMarshalFailure(t *testing.T) {
	old := marshalJSON
	marshalJSON = func(any) ([]byte, error) { return nil, errFake }
	defer func() { marshalJSON = old }()
	if s, err := pageScript(pageConfig{}); !errors.Is(err, errFake) || s != "" {
		t.Errorf("s=%q err=%v", s, err)
	}
	// gather stops there, before it starts a Chrome.
	o := browserOptions{ChromePath: filepath.Join(t.TempDir(), "never-started"), Timeout: time.Second}
	if _, chrome, err := o.gather(context.Background(), pageConfig{}); !errors.Is(err, errFake) || chrome != "" {
		t.Errorf("gather: chrome=%q err=%v", chrome, err)
	}
}

func TestHelloListenerFailureBranches(t *testing.T) {
	oldK, oldC, oldL := genKey, createCert, listenTCP
	defer func() { genKey, createCert, listenTCP = oldK, oldC, oldL }()
	log := &helloLog{}

	genKey = func() (*ecdsa.PrivateKey, error) { return nil, errFake }
	if addr, stop, err := helloListener(log); !errors.Is(err, errFake) || addr != "" || stop != nil {
		t.Errorf("genKey: %q %v %v", addr, stop != nil, err)
	}
	genKey = oldK

	createCert = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) { return nil, errFake }
	if _, stop, err := helloListener(log); !errors.Is(err, errFake) || stop != nil {
		t.Errorf("createCert: %v", err)
	}
	createCert = oldC

	listenTCP = func(string, string) (net.Listener, error) { return nil, errFake }
	if _, stop, err := helloListener(log); !errors.Is(err, errFake) || stop != nil {
		t.Errorf("listen: %v", err)
	}
	// ...and runBrowser reports it instead of going on without a listener.
	var out bytes.Buffer
	err := runBrowser(context.Background(), &out, browserRun{ALPN: true, Opts: browserOptions{Timeout: time.Second}})
	if err == nil || !errors.Is(err, errFake) || !strings.Contains(err.Error(), "alpn listener") {
		t.Errorf("runBrowser: %v", err)
	}
}

// A page that throws (an unparseable iceServers url) is an error from gather,
// with the Chrome version still reported.
func TestGatherPageException(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	o := browserOptions{ChromePath: os.Getenv("TURNPROBE_CHROME"), Timeout: 2 * time.Second, NoSandbox: os.Getenv("CI") != ""}
	_, chrome, err := o.gather(ctx, pageConfig{URLs: []string{"not a turn url"}, TimeoutMs: 1000})
	if err == nil {
		t.Fatal("a page exception passed")
	}
	if !strings.Contains(err.Error(), "exception") && !strings.Contains(strings.ToLower(err.Error()), "syntax") {
		// no Chrome at all reads differently: it never got to the page.
		if chrome == "" {
			if os.Getenv("TURNPROBE_REQUIRE_BROWSER") != "" {
				t.Fatalf("no Chrome: %v", err)
			}
			t.Skipf("no Chrome: %v", err)
		}
		t.Errorf("unexpected error: %v", err)
	}
	if chrome == "" {
		t.Error("the Chrome version was not reported")
	}
}

// The --chrome-flag switches reach Chrome: a host-resolver-rules mapping makes
// a name that resolves nowhere reach the listener, with that name as the SNI.
func TestChromeFlagReachesChrome(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	log := &helloLog{}
	addr, stop, err := helloListener(log)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	_, port, _ := net.SplitHostPort(addr)
	o := browserOptions{ChromePath: os.Getenv("TURNPROBE_CHROME"), Timeout: 5 * time.Second, NoSandbox: os.Getenv("CI") != "",
		Flags: []string{"--host-resolver-rules=MAP turn.chromeflag.test 127.0.0.1"}}
	_, _, err = o.gather(ctx, pageConfig{URLs: []string{"turns:turn.chromeflag.test:" + port + "?transport=tcp"}, Username: "u", Credential: "c", TimeoutMs: 5000})
	if err != nil {
		if os.Getenv("TURNPROBE_REQUIRE_BROWSER") != "" {
			t.Fatalf("no Chrome: %v", err)
		}
		t.Skipf("no Chrome: %v", err)
	}
	h := log.all()
	if len(h) == 0 || h[0].ServerName != "turn.chromeflag.test" {
		t.Errorf("hellos: %+v", h)
	}
}

// TestChromeOffersALPN runs a real Chrome against the hello listener. It skips
// without a Chrome (TURNPROBE_REQUIRE_BROWSER=1 makes that a failure) and
// asserts only that a ClientHello arrived: the ALPN it carries is the
// measurement, logged, not a constant to pin.
func TestChromeOffersALPN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	log := &helloLog{}
	addr, stop, err := helloListener(log)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	o := browserOptions{ChromePath: os.Getenv("TURNPROBE_CHROME"), Timeout: 5 * time.Second, NoSandbox: os.Getenv("CI") != ""}
	g, chrome, err := o.gather(ctx, pageConfig{URLs: []string{"turns:" + addr + "?transport=tcp"}, Username: "u", Credential: "c", TimeoutMs: 5000})
	if err != nil {
		if os.Getenv("TURNPROBE_REQUIRE_BROWSER") != "" {
			t.Fatalf("no Chrome: %v", err)
		}
		t.Skipf("no Chrome: %v", err)
	}
	if judge(g).Pass {
		t.Fatal("a listener that speaks no TURN produced a relay candidate")
	}
	if len(log.all()) == 0 {
		t.Fatalf("Chrome sent no ClientHello; gathered %+v", g)
	}
	t.Logf("%s: %s", chrome, summarizeALPN(log.all()))
}
