//go:build !js

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
)

// The browser lane: the same question as the Go probe, asked by a real Chrome.
// A page makes an RTCPeerConnection with iceTransportPolicy "relay" and one
// iceServer; the server works for a browser if and only if Chrome gathers a
// candidate of type relay. Nothing is relayed to a peer here: an allocation is
// all a relay candidate proves, and it is what a browser needs first.

// iceCandidate is one parsed a=candidate line (RFC 8839 section 5.1).
type iceCandidate struct {
	Raw      string
	Protocol string
	Address  string
	Port     string
	Type     string
}

// parseCandidate reads "candidate:F 1 udp 41885439 192.0.2.1 54321 typ relay
// raddr ... rport ...". It refuses a line without an address, a port and a typ.
func parseCandidate(line string) (iceCandidate, error) {
	c := iceCandidate{Raw: line}
	f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "a="))
	if len(f) < 8 || !strings.HasPrefix(f[0], "candidate:") || f[6] != "typ" {
		return c, fmt.Errorf("not a candidate line: %q", line)
	}
	c.Protocol, c.Address, c.Port, c.Type = strings.ToLower(f[2]), f[4], f[5], f[7]
	return c, nil
}

// iceError is an icecandidateerror event: the url Chrome tried and why it failed.
type iceError struct {
	URL  string `json:"url"`
	Code int    `json:"code"`
	Text string `json:"text"`
	Addr string `json:"addr"`
	Port int    `json:"port"`
}

// gathered is what the page reports.
type gathered struct {
	Candidates []string   `json:"candidates"`
	Errors     []iceError `json:"errors"`
	State      string     `json:"state"`
}

// browserVerdict is PASS iff at least one candidate is of type relay. Lines that
// do not parse are counted, never skipped silently.
type browserVerdict struct {
	Pass     bool
	Relays   []iceCandidate
	Other    int // parsed candidates of another type
	Unparsed int
	Errors   []iceError
	State    string
}

func judge(g gathered) browserVerdict {
	v := browserVerdict{Errors: g.Errors, State: g.State}
	for _, l := range g.Candidates {
		c, err := parseCandidate(l)
		switch {
		case err != nil:
			v.Unparsed++
		case c.Type == "relay":
			v.Relays = append(v.Relays, c)
		default:
			v.Other++
		}
	}
	v.Pass = len(v.Relays) > 0
	return v
}

// line renders the verdict for one server.
func (v browserVerdict) line(raw, chrome string) string {
	if v.Pass {
		addrs := make([]string, len(v.Relays))
		for i, c := range v.Relays {
			addrs[i] = c.Protocol + "/" + net.JoinHostPort(c.Address, c.Port)
		}
		return fmt.Sprintf("PASS %s relay=%s chrome=%s", raw, strings.Join(addrs, ","), chrome)
	}
	var es []string
	for _, e := range v.Errors {
		es = append(es, fmt.Sprintf("%d %q url=%s", e.Code, e.Text, e.URL))
	}
	detail := "no relay candidate"
	if len(es) > 0 {
		detail += "; icecandidateerror: " + strings.Join(es, "; ")
	}
	return fmt.Sprintf("FAIL %s gathering=%s other-candidates=%d unparsed=%d chrome=%s: %s",
		raw, v.State, v.Other, v.Unparsed, chrome, detail)
}

// Seams, replaced by tests that make the failure branches happen.
var (
	marshalJSON = json.Marshal
	genKey      = func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
	createCert  = x509.CreateCertificate
	listenTCP   = net.Listen
)

// pageScript builds the expression run in the page. The configuration travels
// as a JSON literal in the DevTools message (Runtime.evaluate), never in a URL
// or a command line: the page is about:blank.
func pageScript(cfg pageConfig) (string, error) {
	b, err := marshalJSON(cfg)
	if err != nil {
		return "", err
	}
	return "(" + pageFunc + ")(" + string(b) + ")", nil
}

type pageConfig struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
	TimeoutMs  int64    `json:"timeoutMs"`
}

const pageFunc = `async (cfg) => {
  const server = {urls: cfg.urls};
  if (cfg.username) { server.username = cfg.username; server.credential = cfg.credential; }
  const pc = new RTCPeerConnection({iceServers: [server], iceTransportPolicy: "relay"});
  const out = {candidates: [], errors: [], state: ""};
  pc.onicecandidate = (e) => { if (e.candidate) out.candidates.push(e.candidate.candidate); };
  pc.onicecandidateerror = (e) => out.errors.push({url: e.url || "", code: e.errorCode || 0, text: e.errorText || "", addr: e.address || "", port: e.port || 0});
  pc.createDataChannel("probe");
  await pc.setLocalDescription(await pc.createOffer());
  await new Promise((resolve) => {
    if (pc.iceGatheringState === "complete") return resolve();
    pc.addEventListener("icegatheringstatechange", () => { if (pc.iceGatheringState === "complete") resolve(); });
    setTimeout(resolve, cfg.timeoutMs);
  });
  out.state = pc.iceGatheringState;
  pc.close();
  return out;
}`

// browserOptions holds the chrome flags that do not depend on the server.
type browserOptions struct {
	ChromePath string
	NoSandbox  bool
	Flags      []string // extra switches, "name" or "name=value"
	Timeout    time.Duration
}

func (o browserOptions) allocator(ctx context.Context) (context.Context, context.CancelFunc) {
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.Flag("headless", true))
	if o.ChromePath != "" {
		opts = append(opts, chromedp.ExecPath(o.ChromePath))
	}
	if o.NoSandbox || os.Geteuid() == 0 {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}
	for _, f := range o.Flags {
		name, val, hasVal := strings.Cut(strings.TrimLeft(f, "-"), "=")
		if hasVal {
			opts = append(opts, chromedp.Flag(name, val))
		} else {
			opts = append(opts, chromedp.Flag(name, true))
		}
	}
	return chromedp.NewExecAllocator(ctx, opts...)
}

// gather starts a Chrome, loads about:blank, and gathers relay candidates from
// the one iceServer. It returns the Chrome version beside the result.
func (o browserOptions) gather(ctx context.Context, cfg pageConfig) (gathered, string, error) {
	actx, cancelA := o.allocator(ctx)
	defer cancelA()
	bctx, cancelB := chromedp.NewContext(actx)
	defer cancelB()
	bctx, cancelT := context.WithTimeout(bctx, o.Timeout+30*time.Second)
	defer cancelT()

	script, err := pageScript(cfg)
	if err != nil {
		return gathered{}, "", err
	}
	if _, err := chromedp.Run(bctx, chromedp.Navigate("about:blank")); err != nil {
		return gathered{}, "", fmt.Errorf("start chrome: %w", err)
	}
	var product string
	if _, err := chromedp.Run(bctx, chromedp.Func(func(ctx context.Context, tg *chromedp.Target) error {
		r, err := cdp.Call(ctx, tg, browser.GetVersion, cdp.Empty{})
		if err == nil {
			product = r.Product
		}
		return err
	})); err != nil {
		return gathered{}, "", fmt.Errorf("chrome version: %w", err)
	}
	g, err := chromedp.Run(bctx, chromedp.Evaluate[gathered](script, chromedp.EvalAwaitPromise))
	if err != nil {
		return gathered{}, product, err
	}
	return g, product, nil
}

// helloLog records the ALPN protocols of each ClientHello a listener receives.
type helloLog struct {
	mu     sync.Mutex
	hellos []helloRecord
}

type helloRecord struct {
	ServerName string
	ALPN       []string
}

func (l *helloLog) add(h helloRecord) {
	l.mu.Lock()
	l.hellos = append(l.hellos, h)
	l.mu.Unlock()
}

func (l *helloLog) all() []helloRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]helloRecord(nil), l.hellos...)
}

// summarizeALPN is the answer to "which ALPN did Chrome offer": the distinct
// offered lists, or an explicit "no ClientHello seen" (which is not "none").
func summarizeALPN(h []helloRecord) string {
	if len(h) == 0 {
		return "no ClientHello received (not measured)"
	}
	seen := map[string]bool{}
	for _, r := range h {
		if len(r.ALPN) == 0 {
			seen["<no ALPN extension>"] = true
		} else {
			seen["["+strings.Join(r.ALPN, ",")+"]"] = true
		}
	}
	var ks []string
	for k := range seen {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return fmt.Sprintf("%d ClientHello(s), ALPN offered: %s", len(h), strings.Join(ks, " "))
}

// helloListener is a TLS listener on loopback with a throwaway certificate. It
// completes no TURN: it only logs what Chrome's ClientHello carries.
func helloListener(log *helloLog) (addr string, stop func(), err error) {
	key, err := genKey()
	if err != nil {
		return "", nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "alpn-probe"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := createCert(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			log.add(helloRecord{ServerName: h.ServerName, ALPN: append([]string(nil), h.SupportedProtos...)})
			return nil, nil
		},
	}
	ln, err := listenTCP("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				tc := tls.Server(c, cfg)
				if tc.Handshake() == nil {
					_, _ = io.Copy(io.Discard, tc)
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }, nil
}

func startBrowser(ctx context.Context, out io.Writer, targets []target, username, password string, alpn bool, chromePath string, timeout time.Duration) error {
	return runBrowser(ctx, out, browserRun{
		Targets: targets, Username: username, Password: password, ALPN: alpn,
		Opts: browserOptions{ChromePath: chromePath, Flags: chromeFlags, Timeout: timeout},
	})
}

type browserRun struct {
	Targets  []target
	Username string
	Password string
	Opts     browserOptions
	ALPN     bool
}

// runBrowser prints one line per server, then the ALPN measurement if asked.
func runBrowser(ctx context.Context, out io.Writer, r browserRun) error {
	failed := 0
	for _, t := range r.Targets {
		g, chrome, err := r.Opts.gather(ctx, pageConfig{
			URLs: []string{t.Raw}, Username: r.Username, Credential: r.Password,
			TimeoutMs: r.Opts.Timeout.Milliseconds(),
		})
		if err != nil {
			failed++
			fmt.Fprintf(out, "FAIL %s chrome=%s: %v\n", t.Raw, chrome, err)
			continue
		}
		v := judge(g)
		fmt.Fprintln(out, v.line(t.Raw, chrome))
		if !v.Pass {
			failed++
		}
	}
	if r.ALPN {
		log := &helloLog{}
		addr, stop, err := helloListener(log)
		if err != nil {
			return fmt.Errorf("alpn listener: %w", err)
		}
		_, _, err = r.Opts.gather(ctx, pageConfig{
			URLs: []string{"turns:" + addr + "?transport=tcp"}, Username: "alpn", Credential: "alpn",
			TimeoutMs: 5000,
		})
		stop()
		if err != nil {
			fmt.Fprintf(out, "ALPN listener=%s: chrome run failed: %v\n", addr, err)
		} else {
			fmt.Fprintf(out, "ALPN listener=%s: %s\n", addr, summarizeALPN(log.all()))
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d servers failed", failed, len(r.Targets))
	}
	return nil
}
