package server

import (
	"net"
	"net/netip"
	"sync"
)

// deniedPrefixes are the destinations the relay never reaches by default: the
// coturn CVE-2020-26262 class (loopback, private, link-local including the
// cloud metadata address 169.254.169.254, CGNAT, multicast, ULA) plus the
// IPv6 forms that embed an IPv4 address (NAT64, 6to4, Teredo), which would
// otherwise reach the same hosts through a translator.
var deniedPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
	"224.0.0.0/4", "240.0.0.0/4",
	"::/96", "::/128", "::1/128", "100::/64", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	"64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "2001:db8::/32",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// policy decides which peer addresses the relay may reach or hear from.
type policy struct {
	allow []netip.Prefix
	mu    sync.RWMutex
	own   map[netip.Addr]struct{}
}

func newPolicy(allow []netip.Prefix, own []netip.Addr) *policy {
	p := &policy{allow: allow, own: make(map[netip.Addr]struct{})}
	for _, a := range own {
		p.addOwn(a)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ap, ok := netip.AddrFromSlice(ipn.IP); ok {
					p.addOwn(ap)
				}
			}
		}
	}
	return p
}

func norm(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

func (p *policy) addOwn(a netip.Addr) {
	a = norm(a)
	if !a.IsValid() || a.IsUnspecified() {
		return
	}
	p.mu.Lock()
	p.own[a] = struct{}{}
	p.mu.Unlock()
}

// isOwn reports whether a is an address of this server.
func (p *policy) isOwn(a netip.Addr) bool {
	a = norm(a)
	p.mu.RLock()
	_, own := p.own[a]
	p.mu.RUnlock()
	return own
}

// allowlisted reports whether the operator allowed a explicitly.
func (p *policy) allowlisted(a netip.Addr) bool {
	a = norm(a)
	for _, pr := range p.allow {
		if pr.Contains(a) {
			return true
		}
	}
	return false
}

// ownRestricted reports whether a is an address of this server that the
// operator did not allowlist: reachable only at a live relayed port.
func (p *policy) ownRestricted(a netip.Addr) bool {
	return p.isOwn(a) && !p.allowlisted(a)
}

// permitted reports whether a may be a peer. An explicit allowlist entry wins
// over every default refusal (it exists for tests on 127.0.0.1).
func (p *policy) permitted(a netip.Addr) bool {
	a = norm(a)
	if !a.IsValid() {
		return false
	}
	for _, pr := range p.allow {
		if pr.Contains(a) {
			return true
		}
	}
	p.mu.RLock()
	_, own := p.own[a]
	p.mu.RUnlock()
	if own {
		return false
	}
	for _, pr := range deniedPrefixes {
		if pr.Contains(a) {
			return false
		}
	}
	return true
}
