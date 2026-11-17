// Package server implements the TURN server of RFC 8656 with UDP relayed
// transport, reached over UDP, TCP or TLS, plus the STUN Binding answer of
// RFC 8489. Authentication is the long-term credential mechanism with NONCE
// expiry; the credential store is the Config.Auth hook.
//
// Security defaults: the server never relays to or from loopback, 0.0.0.0/8,
// RFC 1918, 100.64/10, link-local (169.254.169.254 included), multicast, ULA,
// the IPv6 translator forms, IPv4-mapped forms of those, or its own
// addresses; it answers 403 Forbidden. Config.AllowPeers re-enables ranges
// (tests relay on 127.0.0.1 with it). Every table is bounded.
package server

import (
	"errors"
	"log/slog"
	"net/netip"
	"time"
)

// Config configures a Server. Realm, Auth and RelayIP are required.
type Config struct {
	// Realm is the long-term credential realm sent in 401 and 438 answers.
	Realm string
	// Auth returns the password of username. Wrap creds.Verify (or any store)
	// in this closure. An unknown user and a wrong password are answered
	// identically (401).
	Auth func(username string) (password string, ok bool)

	// Software is the SOFTWARE attribute value (default "go-turn").
	Software string

	// RelayIP is the address relayed sockets bind to; its family (IPv4 or
	// IPv6) is the only family relayed. RelayAdvertiseIP, if set, is the
	// address reported in XOR-RELAYED-ADDRESS (a NAT'd or floating address).
	RelayIP          netip.Addr
	RelayAdvertiseIP netip.Addr
	// RelayPortMin and RelayPortMax restrict the relayed UDP ports (both zero
	// means any ephemeral port).
	RelayPortMin, RelayPortMax uint16

	// AllowPeers re-enables relaying to and from the listed ranges even when
	// the default policy refuses them (it also overrides the own-address
	// refusal). Empty in production.
	AllowPeers []netip.Prefix
	// OwnAddrs lists extra addresses of this server that peers may not be
	// (interface addresses are discovered automatically).
	OwnAddrs []netip.Addr

	// Quotas and bounds. Zero means the default in parentheses.
	MaxAllocations        int           // total allocations (1000)
	MaxAllocationsPerUser int           // per USERNAME (10)
	DefaultLifetime       time.Duration // (10 min)
	MaxLifetime           time.Duration // cap on any lifetime (1 h)
	MaxBytesPerSecond     int           // per allocation, both directions; -1 disables (4 MiB/s)
	MaxPermissions        int           // per allocation (128)
	MaxChannels           int           // per allocation (128)
	NonceLifetime         time.Duration // (10 min)
	MaxConns              int           // concurrent TCP/TLS connections (1024)
	IdleTimeout           time.Duration // TCP/TLS idle limit once an allocation exists (10 min)
	HandshakeTimeout      time.Duration // TCP/TLS idle limit before any allocation (30 s)
	RelayBufSize          int           // largest relayed datagram (4096)

	// ProxyProtocolFrom lists the sources (a load balancer such as Caddy or
	// HAProxy) whose TCP and TLS connections must begin with a PROXY protocol
	// header (v2 or v1) naming the real client. A connection from a listed
	// source without a valid header is closed; a header from any other
	// source is never honoured (the connection is closed). Once honoured, the
	// header's address is the client address for XOR-MAPPED-ADDRESS, quotas
	// and logs. For ServeTLS the header precedes the ClientHello (TLS is
	// terminated here, not by the proxy). Empty means PROXY protocol is off.
	// It never applies to UDP.
	ProxyProtocolFrom []netip.Prefix

	// Logger receives debug and warning records (default: discard).
	Logger *slog.Logger
	// Now replaces time.Now (tests).
	Now func() time.Time
}

// Protocol limits fixed by RFC 8656.
const (
	permissionLifetime = 5 * time.Minute  // RFC 8656 section 9
	channelLifetime    = 10 * time.Minute // RFC 8656 section 12
)

func (c *Config) withDefaults() error {
	if c.Realm == "" {
		return errors.New("server: Config.Realm is required")
	}
	if c.Auth == nil {
		return errors.New("server: Config.Auth is required")
	}
	if !c.RelayIP.IsValid() {
		return errors.New("server: Config.RelayIP is required")
	}
	c.RelayIP = c.RelayIP.Unmap()
	if c.RelayAdvertiseIP.IsValid() {
		c.RelayAdvertiseIP = c.RelayAdvertiseIP.Unmap()
		if c.RelayAdvertiseIP.Is4() != c.RelayIP.Is4() {
			return errors.New("server: RelayAdvertiseIP and RelayIP differ in family")
		}
	} else {
		c.RelayAdvertiseIP = c.RelayIP
	}
	if c.RelayPortMax < c.RelayPortMin {
		return errors.New("server: RelayPortMax below RelayPortMin")
	}
	def := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	defd := func(p *time.Duration, v time.Duration) {
		if *p == 0 {
			*p = v
		}
	}
	def(&c.MaxAllocations, 1000)
	def(&c.MaxAllocationsPerUser, 10)
	def(&c.MaxBytesPerSecond, 4<<20)
	def(&c.MaxPermissions, 128)
	def(&c.MaxChannels, 128)
	def(&c.MaxConns, 1024)
	def(&c.RelayBufSize, 4096)
	defd(&c.DefaultLifetime, 10*time.Minute)
	defd(&c.MaxLifetime, time.Hour)
	defd(&c.NonceLifetime, 10*time.Minute)
	defd(&c.IdleTimeout, 10*time.Minute)
	defd(&c.HandshakeTimeout, 30*time.Second)
	if c.Software == "" {
		c.Software = "go-turn"
	}
	if c.DefaultLifetime > c.MaxLifetime {
		c.DefaultLifetime = c.MaxLifetime
	}
	if c.RelayBufSize < 576 || c.RelayBufSize > 65000 {
		return errors.New("server: RelayBufSize outside 576..65000")
	}
	for _, p := range c.ProxyProtocolFrom {
		if !p.IsValid() || p.Addr().Is4In6() {
			return errors.New("server: invalid prefix in ProxyProtocolFrom (write an IPv4 prefix in dotted form)")
		}
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return nil
}
