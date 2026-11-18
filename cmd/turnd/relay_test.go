package main

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/go-turn/turn/server"
	"github.com/go-turn/turn/stun"
)

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().String()
}

func TestRunRelayServesBindingAndRefusesAuthless(t *testing.T) {
	addr := freeUDPAddr(t)
	stop, err := runRelay(context.Background(), relayConfig{
		Realm:   "turn.test",
		Auth:    func(u string) (string, bool) { return "pw", u == "u" },
		Options: relayOptions{RelayIP: "127.0.0.1", STUNListen: addr},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ask := func(m *stun.Message) *stun.Message {
		b, _ := m.Encode()
		for i := 0; i < 5; i++ { // the listener starts in a goroutine
			c.Write(b)
			c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			buf := make([]byte, 2048)
			if n, err := c.Read(buf); err == nil {
				r, err := stun.Decode(buf[:n])
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
		}
		t.Fatal("no answer from the relay")
		return nil
	}
	if r := ask(stun.New(stun.ClassRequest, stun.MethodBinding)); r.Class != stun.ClassSuccess {
		t.Fatal("Binding refused")
	}
	alloc := stun.New(stun.ClassRequest, stun.MethodAllocate)
	alloc.AddRequestedTransport(17)
	r := ask(alloc)
	if code, _, _ := r.ErrorCode(); code != 401 {
		t.Fatalf("unauthenticated Allocate answered %d, want 401", code)
	}
	if realm, _ := r.String(stun.AttrRealm); realm != "turn.test" {
		t.Fatalf("realm %q", realm)
	}
}

func TestMaxAllocationAgeFlag(t *testing.T) {
	f := RootCmd().Flags().Lookup("max-allocation-age")
	if f == nil || f.DefValue != "12h0m0s" {
		t.Fatalf("flag %v", f)
	}
	ok := relayOptions{RelayIP: "127.0.0.1", STUNListen: ":0", MaxAllocationAge: time.Hour}
	if err := ok.validate("", ""); err != nil {
		t.Fatal(err)
	}
	ok.MaxAllocationAge = -time.Second
	if err := ok.validate("", ""); err == nil {
		t.Fatal("a negative --max-allocation-age was accepted")
	}
}

func TestRunRelayProxyProtocolFrom(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	stop, err := runRelay(context.Background(), relayConfig{
		Realm: "turn.test",
		Auth:  func(string) (string, bool) { return "", false },
		Options: relayOptions{RelayIP: "127.0.0.1", TURNTCPListen: addr,
			ProxyFrom: []string{"127.0.0.1/32"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	var c net.Conn
	for i := 0; i < 20; i++ { // the listener starts in a goroutine
		if c, err = net.Dial("tcp", addr); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	real := netip.MustParseAddrPort("198.51.100.7:4242")
	b := server.AppendProxyHeaderV2(nil, real, netip.MustParseAddrPort(addr))
	req := stun.New(stun.ClassRequest, stun.MethodBinding)
	rb, _ := req.Encode()
	c.Write(append(b, rb...))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	r, err := stun.Decode(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Addr(stun.AttrXORMappedAddress); got != real {
		t.Fatalf("mapped %v, want the header's %v", got, real)
	}
}

func TestRunRelayOffWithoutListenFlags(t *testing.T) {
	stop, err := runRelay(context.Background(), relayConfig{Realm: "r", Auth: func(string) (string, bool) { return "", false }})
	if err != nil {
		t.Fatal(err)
	}
	stop()
}

func TestRelayOptionsValidate(t *testing.T) {
	cases := []struct {
		name string
		o    relayOptions
		cert string
		ok   bool
	}{
		{"off", relayOptions{}, "", true},
		{"ip without listener", relayOptions{RelayIP: "1.2.3.4"}, "", false},
		{"listener without ip", relayOptions{STUNListen: ":3478"}, "", false},
		{"bad ip", relayOptions{RelayIP: "nope", STUNListen: ":3478"}, "", false},
		{"udp", relayOptions{RelayIP: "203.0.113.5", STUNListen: ":3478"}, "", true},
		{"bad advertise", relayOptions{RelayIP: "203.0.113.5", RelayAdvertiseIP: "x", STUNListen: ":3478"}, "", false},
		{"turns needs cert", relayOptions{RelayIP: "203.0.113.5", TURNSListen: ":443"}, "", false},
		{"turns with cert", relayOptions{RelayIP: "203.0.113.5", TURNSListen: ":443"}, "c", true},
		{"range inverted", relayOptions{RelayIP: "203.0.113.5", STUNListen: ":1", PortMin: 9, PortMax: 3}, "", false},
		{"proxy needs a stream listener", relayOptions{RelayIP: "203.0.113.5", STUNListen: ":3478", ProxyFrom: []string{"127.0.0.1/32"}}, "", false},
		{"proxy with tcp", relayOptions{RelayIP: "203.0.113.5", TURNTCPListen: "127.0.0.1:3478", ProxyFrom: []string{"127.0.0.1/32"}}, "", true},
		{"proxy bad prefix", relayOptions{RelayIP: "203.0.113.5", TURNTCPListen: ":3478", ProxyFrom: []string{"127.0.0.1"}}, "", false},
		{"proxy mapped prefix", relayOptions{RelayIP: "203.0.113.5", TURNTCPListen: ":3478", ProxyFrom: []string{"::ffff:127.0.0.0/104"}}, "", false},
		{"range too high", relayOptions{RelayIP: "203.0.113.5", STUNListen: ":1", PortMax: 70000}, "", false},
	}
	for _, c := range cases {
		err := c.o.validate(c.cert, c.cert)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}
