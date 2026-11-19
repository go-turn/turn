package main

import (
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/go-turn/turn/internal/homepage"
)

// homeConfig derives what the home pages say from turnd's configuration, and
// only public facts from it: the collaboration host is the public URL's, the
// relay's hosts are those of the advertised STUN and TURN URIs, and the
// transports are what those URIs advertise (else the relay's listen ports).
// Secrets, files, limits and counts are never read here.
func homeConfig(cfg config) homepage.Config {
	hc := homepage.Config{CollabURL: strings.TrimRight(cfg.PublicURL, "/"), Secure: strings.HasPrefix(cfg.PublicURL, "https://")}
	if u, err := url.Parse(cfg.PublicURL); err == nil {
		hc.CollabHost = u.Hostname()
	}
	seen := map[homepage.Transport]bool{}
	add := func(kind, port string) {
		if port == "" {
			return
		}
		t := homepage.Transport{Kind: kind, Port: port}
		if !seen[t] {
			seen[t] = true
			hc.Transports = append(hc.Transports, t)
		}
	}
	hosts := map[string]bool{}
	for _, raw := range append(append([]string{}, cfg.STUNURLs...), cfg.TURNURLs...) {
		scheme, rest, ok := strings.Cut(raw, ":")
		if !ok || (scheme != "stun" && scheme != "stuns" && scheme != "turn" && scheme != "turns") {
			continue
		}
		rest, query, _ := strings.Cut(rest, "?")
		host, port, err := net.SplitHostPort(rest)
		if err != nil {
			host, port = strings.Trim(rest, "[]"), "" // no port: the scheme's default
		}
		if host == "" {
			continue
		}
		if !hosts[strings.ToLower(host)] {
			hosts[strings.ToLower(host)] = true
			hc.TurnHosts = append(hc.TurnHosts, host)
		}
		tcp := strings.Contains("&"+query+"&", "&transport=tcp&")
		switch scheme {
		case "stun":
			if port == "" {
				port = "3478"
			}
			add("udp", port)
		case "stuns":
			if port == "" {
				port = "5349"
			}
			add("tls", port)
		case "turn":
			if port == "" {
				port = "3478"
			}
			if tcp {
				add("tcp", port)
			} else {
				add("udp", port)
			}
		case "turns":
			if port == "" {
				port = "5349"
			}
			add("tls", port)
		}
	}
	// The listen flags are only a fallback when no URI is configured: behind a
	// proxy they name private sockets, not what clients are offered. Even then a
	// loopback, private or link-local bind address is never listed.
	if len(cfg.STUNURLs)+len(cfg.TURNURLs) == 0 {
		portOf := func(listen string) string {
			host, p, err := net.SplitHostPort(listen)
			if err != nil {
				return ""
			}
			if ip, err := netip.ParseAddr(host); err == nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
				return ""
			}
			if host == "localhost" {
				return ""
			}
			return p
		}
		add("udp", portOf(cfg.Relay.STUNListen))
		add("tcp", portOf(cfg.Relay.TURNTCPListen))
		add("tls", portOf(cfg.Relay.TURNSListen))
	}
	return hc
}
