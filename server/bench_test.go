package server

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-turn/turn/stun"
)

func benchEnv(b *testing.B) *env {
	return start(b, false, func(c *Config) {
		loopbackAllow(c)
		c.MaxBytesPerSecond = -1
		c.MaxAllocations = 1 << 20
		c.MaxAllocationsPerUser = 1 << 20
	})
}

// BenchmarkAllocate measures allocation setup: an authenticated Allocate
// (relay socket opened, goroutine started) followed by Refresh with LIFETIME 0
// (torn down), from a pool of client sockets. One op is the pair, so allocs/s
// is the reported ops/s. The allocs/op figure includes the in-process test
// client, which pre-encodes its requests to stay negligible.
func BenchmarkAllocate(b *testing.B) {
	e := benchEnv(b)
	const pool = 8
	type cl struct {
		c        *client
		alloc    []byte
		refresh0 []byte
	}
	cls := make([]*cl, pool)
	for i := range cls {
		c := dialUDP(b, e.udp)
		relayedOf(b, c.allocate(nil))
		mustSuccess(b, c.authed(stun.MethodRefresh, func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 0) }))
		a := c.req(stun.MethodAllocate, func(m *stun.Message) { m.AddRequestedTransport(17) })
		r := c.req(stun.MethodRefresh, func(m *stun.Message) { m.AddUint32(stun.AttrLifetime, 0) })
		ab, _ := a.Encode()
		rb, _ := r.Encode()
		cls[i] = &cl{c: c, alloc: ab, refresh0: rb}
	}
	buf := make([]byte, 2048)
	exchange := func(c *client, req []byte) {
		if _, err := c.conn.Write(req); err != nil {
			b.Fatal(err)
		}
		c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.conn.Read(buf); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := cls[i%pool]
		// The same transaction ID is reused: the server sees a fresh
		// allocation each time because the previous one was deleted.
		exchange(x.c, x.alloc)
		exchange(x.c, x.refresh0)
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "allocs/s")
}

// relayBench round-trips packets client -> relay -> echo peer -> relay ->
// client with a bounded window; one op is a round trip (two relayed packets).
func relayBench(b *testing.B, size int, channel bool) {
	e := benchEnv(b)
	peer := echoPeer(b)
	c := dialUDP(b, e.udp)
	relayedOf(b, c.allocate(nil))
	mustSuccess(b, c.permit(peer))
	mustSuccess(b, c.bind(0x4001, peer))
	payload := make([]byte, size)
	var frame []byte
	if channel {
		frame = stun.ChannelData{Number: 0x4001, Data: payload}.AppendTo(nil, false)
	} else {
		m := stun.New(stun.ClassIndication, stun.MethodSend)
		m.AddAddr(stun.AttrXORPeerAddress, peer)
		m.Add(stun.AttrData, payload)
		frame, _ = m.Encode()
	}
	window := make(chan struct{}, 32)
	var got atomic.Int64
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.conn.Read(buf); err != nil {
				close(done)
				return
			}
			got.Add(1)
			<-window
		}
	}()
	b.SetBytes(int64(2 * size))
	b.ReportAllocs()
	b.ResetTimer()
	sent := 0
	for i := 0; i < b.N; i++ {
		select {
		case window <- struct{}{}:
		case <-done:
			b.Fatalf("receiver stopped after %d of %d", got.Load(), b.N)
		}
		if _, err := c.conn.Write(frame); err != nil {
			b.Fatal(err)
		}
		sent++
	}
	for got.Load() < int64(sent) {
		select {
		case <-done:
			b.Fatalf("lost packets: %d of %d returned", got.Load(), sent)
		case <-time.After(time.Millisecond):
		}
	}
	b.StopTimer()
	b.ReportMetric(2*float64(sent)/b.Elapsed().Seconds(), "relayed-pkts/s")
	c.conn.Close()
	<-done
}

func BenchmarkRelay(b *testing.B) {
	for _, size := range []int{64, 512, 1200} {
		b.Run(fmt.Sprintf("ChannelData/%dB", size), func(b *testing.B) { relayBench(b, size, true) })
		b.Run(fmt.Sprintf("SendData/%dB", size), func(b *testing.B) { relayBench(b, size, false) })
	}
}
