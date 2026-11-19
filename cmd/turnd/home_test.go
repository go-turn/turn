package main

import (
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/go-turn/turn/internal/homepage"
	turnv1 "github.com/go-turn/turn/proto/turn/v1"
)

func (d *daemon) getHost(t *testing.T, method, host, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, d.base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	req.Header.Set("Cookie", "lang=en")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// GET / answers with the page of the Host: the relay's for the host the
// advertised URIs name (turn.example in run), the collaboration page for the
// public URL's host and for any other.
func TestHomePageThroughTheDaemon(t *testing.T) {
	d := run(t)
	for _, host := range []string{"turn.example", "turn.example:8081", "127.0.0.1", "stranger.example"} {
		for _, m := range []string{"GET", "HEAD"} {
			resp, body := d.getHost(t, m, host, "/")
			if resp.StatusCode != 200 || resp.Header.Get("Content-Security-Policy") == "" {
				t.Fatalf("%s / on %s: %d", m, host, resp.StatusCode)
			}
			if m == "HEAD" && body != "" {
				t.Fatalf("HEAD body %q", body)
			}
			if m == "GET" {
				relay := strings.Contains(body, "STUN/TURN relay")
				if relay != strings.HasPrefix(host, "turn.example") {
					t.Fatalf("%s: relay page = %v", host, relay)
				}
			}
		}
	}
	_, body := d.getHost(t, "GET", "turn.example", "/")
	// The advertised transports, from the config: udp 3478 (stun and turn dedup).
	if !strings.Contains(body, "UDP") || !strings.Contains(body, "port 3478") || strings.Contains(body, "TLS (turns:)") {
		t.Errorf("relay page transports: %s", body)
	}
	for _, p := range []string{"/nope", "/rooms", "/index.html"} {
		if resp, _ := d.getHost(t, "GET", "stranger.example", p); resp.StatusCode != 404 {
			t.Errorf("GET %s: %d", p, resp.StatusCode)
		}
	}
	if st, b := d.get(t, "/healthz"); st != 200 || b != "ok\n" {
		t.Errorf("healthz %d %q", st, b)
	}
	if resp, _ := d.getHost(t, "GET", "stranger.example", "/login?origin=https://evil.example"); resp.StatusCode != 400 {
		t.Errorf("/login still answers itself: %d", resp.StatusCode)
	}
}

// With a real login and a real room, the pages still hold none of it.
func TestHomePageHoldsNoLiveSecret(t *testing.T) {
	d := run(t)
	token, _ := d.login(t)
	room, err := d.dial(t, origin).CreateRoom(rctx(t, token), &turnv1.CreateRoomRequest{})
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{token, room.Room, room.Token, "client-s3cret", turnSecret, sessionKey}
	// (The public URL, loopback here, is linked from the relay's page: it is a
	// public fact. The client's address is covered in internal/homepage, where
	// the server's and the client's differ.)
	for _, host := range []string{"turn.example", "stranger.example"} {
		resp, body := d.getHost(t, "GET", host, "/?room="+room.Room+"&token="+token)
		if resp.StatusCode != 200 {
			t.Fatal(resp.StatusCode)
		}
		for _, s := range secrets {
			if s != "" && strings.Contains(body, s) {
				t.Errorf("%s: the page contains %q", host, s)
			}
		}
	}
}

func tp(kind, port string) homepage.Transport { return homepage.Transport{Kind: kind, Port: port} }

func TestHomeConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  config
		want homepage.Config
	}{
		{"uris", config{PublicURL: "https://collab.example.org/",
			STUNURLs: []string{"stun:turn.example.org:3478"},
			TURNURLs: []string{"turn:turn.example.org:3478?transport=udp", "turn:turn.example.org:3478?transport=tcp", "turns:turn.example.org:443?transport=tcp", "turns:turn.example.org:443?transport=tcp"}},
			homepage.Config{CollabHost: "collab.example.org", CollabURL: "https://collab.example.org", Secure: true, TurnHosts: []string{"turn.example.org"},
				Transports: []homepage.Transport{tp("udp", "3478"), tp("tcp", "3478"), tp("tls", "443")}}},
		{"default ports and v6", config{PublicURL: "http://localhost:8081",
			STUNURLs: []string{"stun:relay.example"}, TURNURLs: []string{"turns:[2001:db8::1]", "bogus:x", "turn:"}},
			homepage.Config{CollabHost: "localhost", CollabURL: "http://localhost:8081", TurnHosts: []string{"relay.example", "2001:db8::1"},
				Transports: []homepage.Transport{tp("udp", "3478"), tp("tls", "5349")}}},
		{"listen ports", config{PublicURL: "https://c.example", Relay: relayOptions{STUNListen: ":3478", TURNTCPListen: "0.0.0.0:3479", TURNSListen: "[::]:443"}},
			homepage.Config{CollabHost: "c.example", CollabURL: "https://c.example", Secure: true,
				Transports: []homepage.Transport{tp("udp", "3478"), tp("tcp", "3479"), tp("tls", "443")}}},
		// The VM: the TCP listener is loopback behind Caddy, and only the URIs are published.
		{"vm", config{PublicURL: "https://collab.mesocentre.plateau-de-saclay.net",
			Relay:    relayOptions{STUNListen: "157.136.250.7:3478", TURNTCPListen: "127.0.0.1:3478"},
			STUNURLs: []string{"stun:turn.mesocentre.plateau-de-saclay.net:3478"},
			TURNURLs: []string{"turn:turn.mesocentre.plateau-de-saclay.net:3478?transport=udp", "turns:turn.mesocentre.plateau-de-saclay.net:443?transport=tcp"}},
			homepage.Config{CollabHost: "collab.mesocentre.plateau-de-saclay.net", CollabURL: "https://collab.mesocentre.plateau-de-saclay.net", Secure: true,
				TurnHosts:  []string{"turn.mesocentre.plateau-de-saclay.net"},
				Transports: []homepage.Transport{tp("udp", "3478"), tp("tls", "443")}}},
		{"loopback and private listeners are not offered", config{PublicURL: "https://c.example",
			Relay: relayOptions{STUNListen: "10.0.0.5:3478", TURNTCPListen: "127.0.0.1:3478", TURNSListen: "[::1]:443"}},
			homepage.Config{CollabHost: "c.example", CollabURL: "https://c.example", Secure: true}},
		{"nothing", config{PublicURL: "https://c.example"}, homepage.Config{CollabHost: "c.example", CollabURL: "https://c.example", Secure: true}},
	}
	for _, c := range cases {
		if got := homeConfig(c.cfg); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}
