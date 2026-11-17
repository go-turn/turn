package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/go-turn/turn/stun"
)

// Stage names, in the order a probe runs them. A failure names the stage that
// failed, never "something went wrong".
const (
	stageConnect    = "connect"
	stageBinding    = "binding"
	stageAllocate   = "allocate"
	stagePermission = "permission"
	stageRelayAB    = "relay A->B"
	stageRelayBA    = "relay B->A"
)

// stageError is a failure with the stage it happened in.
type stageError struct {
	Stage string
	Err   error
}

func (e *stageError) Error() string { return e.Stage + ": " + e.Err.Error() }
func (e *stageError) Unwrap() error { return e.Err }

func fail(stage string, format string, a ...any) error {
	return &stageError{Stage: stage, Err: fmt.Errorf(format, a...)}
}

// target is a parsed --server: turn:host[:port]?transport=udp|tcp or
// turns:host[:port]?transport=tcp (RFC 7064 and RFC 7065 URIs).
type target struct {
	Raw       string
	Scheme    string // "turn" or "turns"
	Host      string
	Port      string
	Transport string // "udp" or "tcp"
}

func (t target) hostPort() string { return net.JoinHostPort(t.Host, t.Port) }

// parseServer reads a TURN URI. turns over UDP (DTLS) is not spoken here.
func parseServer(raw string) (target, error) {
	t := target{Raw: raw}
	rest, query, _ := strings.Cut(raw, "?")
	scheme, hp, ok := strings.Cut(rest, ":")
	if !ok || (scheme != "turn" && scheme != "turns") || hp == "" || strings.HasPrefix(hp, "//") {
		return t, fmt.Errorf("%q: want turn:host:port?transport=udp|tcp or turns:host:port?transport=tcp", raw)
	}
	t.Scheme = scheme
	host, port, err := net.SplitHostPort(hp)
	if err != nil {
		// no port: the whole of hp is the host (an IPv6 literal keeps its brackets).
		host, port = strings.Trim(hp, "[]"), ""
	}
	if host == "" || strings.ContainsAny(host, "/@ \t") {
		return t, fmt.Errorf("%q: bad host", raw)
	}
	if port == "" {
		port = "3478"
		if scheme == "turns" {
			port = "5349"
		}
	}
	t.Host, t.Port = host, port
	if p, err := net.LookupPort("tcp", port); err != nil || p == 0 {
		return t, fmt.Errorf("%q: bad port", raw)
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return t, fmt.Errorf("%q: bad query: %v", raw, err)
	}
	for k := range q {
		if k != "transport" {
			return t, fmt.Errorf("%q: unknown parameter %q", raw, k)
		}
	}
	t.Transport = q.Get("transport")
	if t.Transport == "" {
		t.Transport = "udp"
		if scheme == "turns" {
			t.Transport = "tcp"
		}
	}
	switch {
	case t.Transport != "udp" && t.Transport != "tcp":
		return t, fmt.Errorf("%q: transport must be udp or tcp", raw)
	case scheme == "turns" && t.Transport != "tcp":
		return t, fmt.Errorf("%q: turns is TLS over TCP (DTLS is not supported)", raw)
	}
	return t, nil
}

// credentials are the long-term credentials of the probe.
type credentials struct {
	Username, Password, Realm string
}

// result is what a successful probe learned.
type result struct {
	Mapped         netip.AddrPort // what the server saw: the Binding answer
	RelayA, RelayB netip.AddrPort
	RoundTrip      time.Duration // A->B and B->A, both legs
}

// probeConfig carries the knobs a test turns.
type probeConfig struct {
	Timeout time.Duration
	// RootCAs verifies a turns: certificate; nil is the system roots.
	RootCAs *x509.CertPool
}

// conn is a TURN client over one connection: datagrams for UDP, framed STUN
// for TCP and TLS.
type conn struct {
	nc     net.Conn
	stream bool
	buf    []byte
	queue  [][]byte
	creds  credentials
	nonce  string
	wait   time.Duration // one wait for a response; UDP retransmits within the timeout
	tries  int
}

func dial(ctx context.Context, t target, pc probeConfig) (*conn, error) {
	d := net.Dialer{Timeout: pc.Timeout}
	var nc net.Conn
	var err error
	switch {
	case t.Scheme == "turns":
		td := tls.Dialer{NetDialer: &d, Config: &tls.Config{ServerName: t.Host, RootCAs: pc.RootCAs, MinVersion: tls.VersionTLS12}}
		nc, err = td.DialContext(ctx, "tcp", t.hostPort())
	default:
		nc, err = d.DialContext(ctx, t.Transport, t.hostPort())
	}
	if err != nil {
		return nil, fail(stageConnect, "%v", err)
	}
	c := &conn{nc: nc, stream: t.Transport == "tcp", wait: pc.Timeout, tries: 1}
	if !c.stream {
		c.tries = 4 // UDP loses datagrams: the same transaction is retransmitted
		c.wait = pc.Timeout / time.Duration(c.tries)
	}
	return c, nil
}

func (c *conn) close() { c.nc.Close() }

func (c *conn) write(b []byte) error {
	c.nc.SetWriteDeadline(time.Now().Add(c.wait))
	_, err := c.nc.Write(b)
	return err
}

// recv returns the next frame (a copy), or nil at the deadline.
func (c *conn) recv(d time.Duration) ([]byte, error) {
	if len(c.queue) > 0 {
		f := c.queue[0]
		c.queue = c.queue[1:]
		return f, nil
	}
	c.nc.SetReadDeadline(time.Now().Add(d))
	if c.stream {
		f, nb, err := stun.ReadFrame(c.nc, c.buf)
		c.buf = nb
		if err != nil {
			if isTimeout(err) {
				return nil, nil
			}
			return nil, err
		}
		return append([]byte(nil), f...), nil
	}
	b := make([]byte, 65535)
	n, err := c.nc.Read(b)
	if err != nil {
		if isTimeout(err) {
			return nil, nil
		}
		return nil, err
	}
	return b[:n], nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// do sends m and returns the response with its transaction ID; unrelated
// frames (a Data indication that arrived early) are queued for later.
func (c *conn) do(m *stun.Message) (*stun.Message, error) {
	b, err := m.Encode()
	if err != nil {
		return nil, err
	}
	var skipped [][]byte
	defer func() { c.queue = append(skipped, c.queue...) }()
	for try := 0; try < c.tries; try++ {
		if err := c.write(b); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(c.wait)
		for {
			left := time.Until(deadline)
			if left <= 0 {
				break
			}
			f, err := c.recv(left)
			if err != nil {
				return nil, err
			}
			if f == nil {
				break
			}
			if stun.IsMessage(f) {
				if r, err := stun.Decode(f); err == nil && r.TxID == m.TxID &&
					(r.Class == stun.ClassSuccess || r.Class == stun.ClassError) {
					return r, nil
				}
			}
			skipped = append(skipped, f)
		}
	}
	return nil, fmt.Errorf("no response within %v", time.Duration(c.tries)*c.wait)
}

// errText is "403 Forbidden" for an error response.
func errText(r *stun.Message) string {
	code, reason, err := r.ErrorCode()
	if err != nil {
		return "an error response without ERROR-CODE"
	}
	return fmt.Sprintf("%d %s", code, reason)
}

// binding asks the server which address it sees us at (RFC 8489 section 6).
func (c *conn) binding() (netip.AddrPort, error) {
	r, err := c.do(stun.New(stun.ClassRequest, stun.MethodBinding))
	if err != nil {
		return netip.AddrPort{}, fail(stageBinding, "%v", err)
	}
	if r.Class != stun.ClassSuccess {
		return netip.AddrPort{}, fail(stageBinding, "%s", errText(r))
	}
	a, err := r.Addr(stun.AttrXORMappedAddress)
	if err != nil {
		return netip.AddrPort{}, fail(stageBinding, "no XOR-MAPPED-ADDRESS in the answer: %v", err)
	}
	return a, nil
}

// authed sends a request under the long-term credential mechanism (RFC 8656
// section 5.1): the first try learns the realm and nonce from a 401, the
// second is signed. A stale nonce (438) is answered once.
func (c *conn) authed(stage string, method stun.Method, fill func(*stun.Message)) (*stun.Message, error) {
	build := func() *stun.Message {
		m := stun.New(stun.ClassRequest, method)
		if fill != nil {
			fill(m)
		}
		if c.nonce != "" {
			m.AddString(stun.AttrUsername, c.creds.Username)
			m.AddString(stun.AttrRealm, c.creds.Realm)
			m.AddString(stun.AttrNonce, c.nonce)
			m.SetIntegrity(stun.LongTermKeyMD5(c.creds.Username, c.creds.Realm, c.creds.Password))
		}
		return m
	}
	r, err := c.do(build())
	for i := 0; err == nil && i < 2; i++ {
		code, _, cerr := r.ErrorCode()
		if r.Class != stun.ClassError || cerr != nil || (code != 401 && code != 438) {
			break
		}
		nonce, ok := r.String(stun.AttrNonce)
		if !ok {
			break
		}
		if realm, _ := r.String(stun.AttrRealm); realm != "" && realm != c.creds.Realm {
			return nil, fail(stage, "the server's realm is %q, not --realm %q", realm, c.creds.Realm)
		}
		if code == 401 && c.nonce != "" {
			break // signed already and refused: the credentials are wrong
		}
		c.nonce = nonce
		r, err = c.do(build())
	}
	if err != nil {
		return nil, fail(stage, "%v", err)
	}
	if r.Class != stun.ClassSuccess {
		return nil, fail(stage, "%s", errText(r))
	}
	return r, nil
}

// allocate opens a UDP allocation and returns its relayed address.
func (c *conn) allocate() (netip.AddrPort, error) {
	r, err := c.authed(stageAllocate, stun.MethodAllocate, func(m *stun.Message) { m.AddRequestedTransport(17) })
	if err != nil {
		return netip.AddrPort{}, err
	}
	a, err := r.Addr(stun.AttrXORRelayedAddress)
	if err != nil {
		return netip.AddrPort{}, fail(stageAllocate, "no XOR-RELAYED-ADDRESS in the answer: %v", err)
	}
	return a, nil
}

func (c *conn) permit(peer netip.AddrPort) error {
	_, err := c.authed(stagePermission, stun.MethodCreatePermission, func(m *stun.Message) {
		m.AddAddr(stun.AttrXORPeerAddress, peer)
	})
	return err
}

// release deletes the allocation (Refresh with LIFETIME 0); best effort.
func (c *conn) release() {
	if c.nonce == "" {
		return
	}
	_, _ = c.authed("release", stun.MethodRefresh, func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 0) })
}

// sendInd relays data to peer with a Send indication (RFC 8656 section 11).
func (c *conn) sendInd(peer netip.AddrPort, data []byte) error {
	m := stun.New(stun.ClassIndication, stun.MethodSend)
	m.AddAddr(stun.AttrXORPeerAddress, peer)
	m.Add(stun.AttrData, data)
	b, err := m.Encode()
	if err != nil {
		return err
	}
	return c.write(b)
}

// await waits for a Data indication from a peer on fromPort carrying want.
func (c *conn) await(d time.Duration, fromPort uint16, want []byte) bool {
	deadline := time.Now().Add(d)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return false
		}
		f, err := c.recv(left)
		if err != nil || f == nil {
			return false
		}
		if !stun.IsMessage(f) {
			continue
		}
		m, err := stun.Decode(f)
		if err != nil || m.Class != stun.ClassIndication || m.Method != stun.MethodData {
			continue
		}
		// The peer address is the source the relay saw: the relayed port of the
		// sender. Its IP may be the bind address behind a NAT, so the port and
		// the payload are the proof.
		p, perr := m.Addr(stun.AttrXORPeerAddress)
		v, _ := m.Get(stun.AttrData)
		if perr == nil && p.Port() == fromPort && string(v) == string(want) {
			return true
		}
	}
}

// hop sends a fresh datagram from one allocation to the other's relayed
// address and waits for it. UDP is lossy, so it is repeated within the timeout.
func hop(stage string, from, to *conn, toRelay, fromRelay netip.AddrPort, timeout time.Duration) error {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	payload := []byte(stage + " " + hex.EncodeToString(nonce[:]))
	const tries = 4
	for i := 0; i < tries; i++ {
		if err := from.sendInd(toRelay, payload); err != nil {
			return fail(stage, "%v", err)
		}
		if to.await(timeout/tries, fromRelay.Port(), payload) {
			return nil
		}
	}
	return fail(stage, "the datagram sent to %v did not come out of the other allocation within %v", toRelay, timeout)
}

// probe runs every stage against one server.
func probe(ctx context.Context, t target, cr credentials, pc probeConfig) (res result, err error) {
	a, err := dial(ctx, t, pc)
	if err != nil {
		return res, err
	}
	defer a.close()
	if res.Mapped, err = a.binding(); err != nil {
		return res, err
	}
	b, err := dial(ctx, t, pc)
	if err != nil {
		return res, err
	}
	defer b.close()
	a.creds, b.creds = cr, cr
	if res.RelayA, err = a.allocate(); err != nil {
		return res, err
	}
	defer a.release()
	if res.RelayB, err = b.allocate(); err != nil {
		return res, err
	}
	defer b.release()
	if err = a.permit(res.RelayB); err != nil {
		return res, err
	}
	if err = b.permit(res.RelayA); err != nil {
		return res, err
	}
	start := time.Now()
	if err = hop(stageRelayAB, a, b, res.RelayB, res.RelayA, pc.Timeout); err != nil {
		return res, err
	}
	if err = hop(stageRelayBA, b, a, res.RelayA, res.RelayB, pc.Timeout); err != nil {
		return res, err
	}
	res.RoundTrip = time.Since(start)
	return res, nil
}
