package server

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

// PROXY protocol, as specified in haproxy's doc/proxy-protocol.txt (sections
// 2.1 and 2.2). A load balancer in front of the server (Caddy with caddy-l4,
// HAProxy) prepends one header to a TCP connection that carries the real
// client address; the server honours it only from Config.ProxyProtocolFrom.

// Header bounds. The v2 address block is 12 bytes (IPv4) or 36 (IPv6); the
// rest is TLVs, which are skipped. The specification sets no maximum, so the
// server refuses a block above maxProxyBlock rather than read what a peer
// claims. v1 lines are at most 107 bytes including CRLF.
const (
	maxProxyBlock = 512
	maxProxyV1    = 107
)

// Errors of the header reader. Every one closes the connection.
var (
	ErrProxyHeader = errors.New("server: malformed PROXY protocol header")
	ErrProxyFamily = errors.New("server: PROXY protocol family or transport not supported")
)

var proxySig = []byte("\r\n\r\n\x00\r\nQUIT\n")

// proxyHeader is a parsed header. Local means the connection was made by the
// proxy itself (a health check): use the real endpoints.
type proxyHeader struct {
	Local bool
	Src   netip.AddrPort
}

// readProxyHeader reads exactly one PROXY header from r and nothing after it,
// so the bytes that follow are the client's own stream. v2 is binary, v1 text.
func readProxyHeader(r io.Reader) (proxyHeader, error) {
	var first [6]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return proxyHeader{}, ErrProxyHeader
	}
	switch {
	case bytes.Equal(first[:], proxySig[:6]):
		return readProxyV2(r)
	case string(first[:]) == "PROXY ":
		return readProxyV1(r)
	}
	return proxyHeader{}, ErrProxyHeader
}

func readProxyV2(r io.Reader) (proxyHeader, error) {
	var h [10]byte // rest of the 16-byte fixed part
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return proxyHeader{}, ErrProxyHeader
	}
	if !bytes.Equal(h[:6], proxySig[6:]) {
		return proxyHeader{}, ErrProxyHeader
	}
	verCmd, famProto := h[6], h[7]
	n := int(binary.BigEndian.Uint16(h[8:10]))
	if verCmd>>4 != 2 {
		return proxyHeader{}, ErrProxyHeader
	}
	if n > maxProxyBlock {
		return proxyHeader{}, ErrProxyHeader
	}
	block := make([]byte, n)
	if _, err := io.ReadFull(r, block); err != nil {
		return proxyHeader{}, ErrProxyHeader
	}
	switch verCmd & 0x0f {
	case 0x0: // LOCAL: accept, use the real endpoints, discard the block
		return proxyHeader{Local: true}, nil
	case 0x1: // PROXY
	default:
		return proxyHeader{}, ErrProxyHeader
	}
	switch famProto {
	case 0x00: // AF_UNSPEC: no addresses; use the real endpoints
		return proxyHeader{Local: true}, nil
	case 0x11: // TCP over IPv4
		if n < 12 {
			return proxyHeader{}, ErrProxyHeader
		}
		src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(block[0:4])), binary.BigEndian.Uint16(block[8:10]))
		return checkSrc(src)
	case 0x21: // TCP over IPv6
		if n < 36 {
			return proxyHeader{}, ErrProxyHeader
		}
		src := netip.AddrPortFrom(netip.AddrFrom16([16]byte(block[0:16])), binary.BigEndian.Uint16(block[32:34]))
		return checkSrc(src)
	}
	// UDP (0x12, 0x22), UNIX (0x31, 0x32) and every unknown value.
	return proxyHeader{}, ErrProxyFamily
}

func checkSrc(src netip.AddrPort) (proxyHeader, error) {
	a := src.Addr().Unmap()
	if a.IsUnspecified() || a.IsMulticast() || src.Port() == 0 {
		return proxyHeader{}, ErrProxyHeader
	}
	return proxyHeader{Src: netip.AddrPortFrom(a, src.Port())}, nil
}

// readProxyV1 reads the rest of "PROXY <proto> <src> <dst> <sport> <dport>\r\n"
// one byte at a time (the line must not swallow the client's first bytes).
func readProxyV1(r io.Reader) (proxyHeader, error) {
	line := []byte("PROXY ")
	var b [1]byte
	for {
		if len(line) >= maxProxyV1 {
			return proxyHeader{}, ErrProxyHeader
		}
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return proxyHeader{}, ErrProxyHeader
		}
		line = append(line, b[0])
		if b[0] == '\n' {
			break
		}
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return proxyHeader{}, ErrProxyHeader
	}
	f := bytes.Fields(line[:len(line)-2])
	if len(f) >= 2 && string(f[1]) == "UNKNOWN" {
		return proxyHeader{Local: true}, nil
	}
	if len(f) != 6 || (string(f[1]) != "TCP4" && string(f[1]) != "TCP6") {
		return proxyHeader{}, ErrProxyHeader
	}
	src, err := netip.ParseAddr(string(f[2]))
	if err != nil || src.Is4() != (string(f[1]) == "TCP4") || src.Is4In6() {
		return proxyHeader{}, ErrProxyHeader
	}
	if _, err := netip.ParseAddr(string(f[3])); err != nil {
		return proxyHeader{}, ErrProxyHeader
	}
	sp, err := parsePort(f[4])
	if err != nil {
		return proxyHeader{}, err
	}
	if _, err := parsePort(f[5]); err != nil {
		return proxyHeader{}, err
	}
	return checkSrc(netip.AddrPortFrom(src, sp))
}

func parsePort(b []byte) (uint16, error) {
	if len(b) == 0 || len(b) > 5 || (len(b) > 1 && b[0] == '0') {
		return 0, ErrProxyHeader
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, ErrProxyHeader
		}
		n = n*10 + int(c-'0')
	}
	if n > 65535 {
		return 0, ErrProxyHeader
	}
	return uint16(n), nil
}

// AppendProxyHeaderV2 appends a PROXY command header for a TCP connection
// from src to dst, for a proxy written in Go and for tests.
func AppendProxyHeaderV2(b []byte, src, dst netip.AddrPort) []byte {
	b = append(b, proxySig...)
	if src.Addr().Unmap().Is4() && dst.Addr().Unmap().Is4() {
		b = append(b, 0x21, 0x11, 0, 12)
		s, d := src.Addr().Unmap().As4(), dst.Addr().Unmap().As4()
		b = append(b, s[:]...)
		b = append(b, d[:]...)
	} else {
		b = append(b, 0x21, 0x21, 0, 36)
		s, d := src.Addr().As16(), dst.Addr().As16()
		b = append(b, s[:]...)
		b = append(b, d[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, src.Port())
	return binary.BigEndian.AppendUint16(b, dst.Port())
}
