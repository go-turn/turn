package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/go-turn/turn/server"
)

// relayOptions are the relay's own flags. The relay is off unless at least
// one listen address is set.
type relayOptions struct {
	// RelayIP is the address relayed sockets bind to (IPv4 or IPv6);
	// RelayAdvertiseIP is the one reported to clients when it differs (NAT).
	RelayIP, RelayAdvertiseIP string
	// STUNListen is the UDP address for STUN and TURN over UDP (":3478");
	// TURNTCPListen serves TURN over TCP; TURNSListen serves it over TLS
	// (turns:, port 443) with the TLS certificate flags.
	STUNListen, TURNTCPListen, TURNSListen string
	PortMin, PortMax                       uint
	// ProxyFrom lists the prefixes (--proxy-protocol-from) whose TCP and TLS
	// connections carry a PROXY protocol header; empty is off.
	ProxyFrom []string
	// MaxAllocationAge (--max-allocation-age) bounds how long an allocation may
	// be kept alive, past the expiry of its credential included; zero is the
	// server's default (12 h).
	MaxAllocationAge time.Duration
}

func (o relayOptions) proxyPrefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range o.ProxyFrom {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Is4In6() {
			return nil, fmt.Errorf("--proxy-protocol-from %q: want a prefix such as 127.0.0.1/32 or ::1/128", s)
		}
		out = append(out, p)
	}
	return out, nil
}

func (o relayOptions) enabled() bool {
	return o.STUNListen != "" || o.TURNTCPListen != "" || o.TURNSListen != ""
}

func (o relayOptions) validate(tlsCert, tlsKey string) error {
	if _, err := o.proxyPrefixes(); err != nil {
		return err
	}
	if len(o.ProxyFrom) > 0 && o.TURNTCPListen == "" && o.TURNSListen == "" {
		return errors.New("--proxy-protocol-from needs --turn-tcp-listen or --turns-listen (it never applies to UDP)")
	}
	if !o.enabled() {
		if o.RelayIP != "" {
			return errors.New("--relay-ip needs --stun-listen, --turn-tcp-listen or --turns-listen")
		}
		return nil
	}
	if _, err := netip.ParseAddr(o.RelayIP); err != nil {
		return errors.New("--relay-ip must be the address relayed sockets bind to")
	}
	if o.RelayAdvertiseIP != "" {
		if _, err := netip.ParseAddr(o.RelayAdvertiseIP); err != nil {
			return errors.New("--relay-advertise-ip is not an IP address")
		}
	}
	if o.TURNSListen != "" && (tlsCert == "" || tlsKey == "") {
		return errors.New("--turns-listen needs --tls-cert-file and --tls-key-file")
	}
	if o.MaxAllocationAge < 0 {
		return errors.New("--max-allocation-age must not be negative")
	}
	if o.PortMin > 65535 || o.PortMax > 65535 || o.PortMax < o.PortMin {
		return errors.New("--relay-port-min/--relay-port-max: want 0 <= min <= max <= 65535")
	}
	return nil
}

// runRelay builds the TURN server from the HTTP half's realm and credential
// hook and serves it on the configured sockets. It is the body of the seam.
func runRelay(ctx context.Context, rc relayConfig) (func(), error) {
	o := rc.Options
	if !o.enabled() {
		return func() {}, nil
	}
	cfg := server.Config{
		Realm:            rc.Realm,
		Auth:             rc.Auth,
		AuthExisting:     rc.AuthExisting,
		MaxAllocationAge: o.MaxAllocationAge,
		RelayIP:          netip.MustParseAddr(o.RelayIP),
		RelayPortMin:     uint16(o.PortMin),
		RelayPortMax:     uint16(o.PortMax),
	}
	if o.RelayAdvertiseIP != "" {
		cfg.RelayAdvertiseIP = netip.MustParseAddr(o.RelayAdvertiseIP)
	}
	var err error
	if cfg.ProxyProtocolFrom, err = o.proxyPrefixes(); err != nil {
		return nil, err
	}
	cfg.Logger = rc.Logger
	if rc.Observer != nil {
		cfg.Observer = rc.Observer
	}
	srv, err := server.New(cfg)
	if err != nil {
		return nil, err
	}
	if rc.OnServer != nil {
		rc.OnServer(srv)
	}
	var closers []func() error
	stop := func() {
		srv.Close()
		for _, c := range closers {
			c()
		}
	}
	fail := func(err error) (func(), error) { stop(); return nil, err }

	if o.STUNListen != "" {
		pc, err := net.ListenPacket("udp", o.STUNListen)
		if err != nil {
			return fail(fmt.Errorf("--stun-listen: %w", err))
		}
		closers = append(closers, pc.Close)
		go srv.ServePacketConn(pc)
	}
	if o.TURNTCPListen != "" {
		ln, err := net.Listen("tcp", o.TURNTCPListen)
		if err != nil {
			return fail(fmt.Errorf("--turn-tcp-listen: %w", err))
		}
		closers = append(closers, ln.Close)
		go srv.ServeListener(ln)
	}
	if o.TURNSListen != "" {
		cert, err := tls.LoadX509KeyPair(rc.TLSCertFile, rc.TLSKeyFile)
		if err != nil {
			return fail(fmt.Errorf("turns certificate: %w", err))
		}
		ln, err := net.Listen("tcp", o.TURNSListen)
		if err != nil {
			return fail(fmt.Errorf("--turns-listen: %w", err))
		}
		closers = append(closers, ln.Close)
		go srv.ServeTLS(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	go func() { <-ctx.Done(); stop() }()
	return stop, nil
}
