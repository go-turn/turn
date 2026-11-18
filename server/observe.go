package server

import (
	"net/netip"
	"time"

	"github.com/go-turn/turn/stun"
)

// Observer is told about every finished TURN control request (Allocate,
// Refresh, CreatePermission, ChannelBind). It is never called per relayed
// packet: those are the Stats counters. A nil Observer costs nothing.
//
// The record carries no address, username, nonce or credential, so an
// implementation can export it as it is.
type Observer interface {
	Request(RequestInfo)
}

// RequestInfo describes one finished control request.
type RequestInfo struct {
	// Method is "allocate", "refresh", "create_permission", "channel_bind" or
	// "other" (a method the server does not serve).
	Method string
	// Transport is "udp", "tcp" or "tls": how the client reached the server.
	Transport string
	// Code is the STUN error code of the answer (RFC 8489 section 14.8), or 0
	// for a success.
	Code int
	// Policy classes a 403 caused by the peer-address policy: "loopback",
	// "private", "link_local", "metadata", "cgnat", "multicast", "translator",
	// "own_address", "reserved" or "port_zero". A 443 is "family_mismatch".
	// Empty for every other answer.
	Policy string
	// Received is when the request was taken off the wire; End is when it was
	// answered.
	Received, End time.Time
}

func methodName(m stun.Method) string {
	switch m {
	case stun.MethodAllocate:
		return "allocate"
	case stun.MethodRefresh:
		return "refresh"
	case stun.MethodCreatePermission:
		return "create_permission"
	case stun.MethodChannelBind:
		return "channel_bind"
	}
	return "other"
}

func (s *Server) observe(tr transport, req *stun.Message, code int, policy string) {
	if s.cfg.Observer == nil || req.Class != stun.ClassRequest {
		return
	}
	info := RequestInfo{Method: methodName(req.Method), Transport: tr.name(), Code: code, Policy: policy, End: time.Now()}
	if t, ok := tr.(*timedTransport); ok {
		info.Received = t.received
	}
	s.cfg.Observer.Request(info)
}

// timedTransport is a transport that remembers when the request being served
// was read. It exists only while an Observer is set.
type timedTransport struct {
	transport
	received time.Time
}

var (
	metadataAddrs = []netip.Addr{netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("fd00:ec2::254")}
	cgnat         = netip.MustParsePrefix("100.64.0.0/10")
	translators   = mustPrefixes("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32")
)

// class names why a peer address is refused, for Observer.
func (p *policy) class(a netip.Addr) string {
	a = norm(a)
	// The address's own nature comes first: 127.0.0.1 is also an address of
	// this host, but "loopback" is the more useful answer. "own_address" is
	// the server's other addresses (its public one, say).
	switch {
	case a.IsLoopback():
		return "loopback"
	case a == metadataAddrs[0] || a == metadataAddrs[1]:
		return "metadata"
	case a.IsLinkLocalUnicast():
		return "link_local"
	case a.IsPrivate():
		return "private"
	case cgnat.Contains(a):
		return "cgnat"
	case a.IsMulticast():
		return "multicast"
	}
	for _, pr := range translators {
		if pr.Contains(a) {
			return "translator"
		}
	}
	if p.ownRestricted(a) {
		return "own_address"
	}
	return "reserved"
}

// Usage is the live permissions and channel bindings, summed over every
// allocation. It walks the allocations, so call it at a slow rate (a metrics
// scrape), not per packet.
type Usage struct {
	Permissions, Channels int
}

// Usage returns the live permissions and channel bindings.
func (s *Server) Usage() Usage {
	var u Usage
	now := s.cfg.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.allocs {
		a.mu.Lock()
		for _, exp := range a.perms {
			if now.Before(exp) {
				u.Permissions++
			}
		}
		for _, c := range a.byNum {
			if now.Before(c.expires) {
				u.Channels++
			}
		}
		a.mu.Unlock()
	}
	return u
}
