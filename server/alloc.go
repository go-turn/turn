package server

import (
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/go-turn/turn/stun"
)

type channel struct {
	number  uint16
	peer    netip.AddrPort
	expires time.Time
}

// allocation is one TURN allocation: a relayed UDP socket plus the
// permissions and channel bindings that gate it.
type allocation struct {
	s      *Server
	key    fiveTuple
	user   string
	tr     transport
	client netip.AddrPort

	relay     *net.UDPConn
	relayAddr netip.AddrPort // the address advertised to the client

	mu      sync.Mutex
	expires time.Time
	perms   map[netip.Addr]time.Time
	byNum   map[uint16]*channel
	byPeer  map[netip.AddrPort]*channel
	txid    stun.TxID // Allocate transaction, for retransmissions
	resp    []byte
	rate    bucket

	once sync.Once
}

// bucket is a token bucket in bytes per second with one second of burst.
type bucket struct {
	rate   float64 // bytes per second; <= 0 disables
	tokens float64
	last   time.Time
}

func (b *bucket) allow(n int, now time.Time) bool {
	if b.rate <= 0 {
		return true
	}
	if b.last.IsZero() {
		b.tokens, b.last = b.rate, now
	}
	if dt := now.Sub(b.last).Seconds(); dt > 0 {
		b.tokens = min(b.rate, b.tokens+dt*b.rate)
		b.last = now
	}
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

func (a *allocation) expired(now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !now.Before(a.expires)
}

func (a *allocation) prune(now time.Time) {
	a.mu.Lock()
	for ip, exp := range a.perms {
		if !now.Before(exp) {
			delete(a.perms, ip)
		}
	}
	for n, c := range a.byNum {
		if !now.Before(c.expires) {
			delete(a.byNum, n)
			if a.byPeer[c.peer] == c {
				delete(a.byPeer, c.peer)
			}
		}
	}
	a.mu.Unlock()
}

func (a *allocation) close() {
	a.once.Do(func() { a.relay.Close() })
}

// permitted reports whether a live permission covers ip. Permissions are only
// ever installed for addresses the policy allows, so this also enforces
// "never relay to or from" the refused ranges.
func (a *allocation) permittedLocked(ip netip.Addr, now time.Time) bool {
	exp, ok := a.perms[ip]
	return ok && now.Before(exp)
}

// fromClientChannel relays a ChannelData frame to its bound peer.
func (a *allocation) fromClientChannel(cd stun.ChannelData) {
	now := a.s.cfg.Now()
	a.mu.Lock()
	ch := a.byNum[cd.Number]
	ok := ch != nil && now.Before(ch.expires) && a.rate.allow(len(cd.Data), now)
	var peer netip.AddrPort
	if ok {
		peer = ch.peer
	}
	a.mu.Unlock()
	if !ok {
		a.s.st.dropped.Add(1)
		return
	}
	a.toPeer(peer, cd.Data)
}

// fromClientSend relays a Send indication's payload.
func (a *allocation) fromClientSend(peer netip.AddrPort, data []byte) {
	now := a.s.cfg.Now()
	a.mu.Lock()
	ok := a.permittedLocked(peer.Addr(), now) && a.rate.allow(len(data), now)
	a.mu.Unlock()
	if !ok || peer.Port() == 0 {
		a.s.st.dropped.Add(1)
		return
	}
	a.toPeer(peer, data)
}

func (a *allocation) toPeer(peer netip.AddrPort, data []byte) {
	if _, err := a.relay.WriteToUDPAddrPort(data, peer); err != nil {
		a.s.st.dropped.Add(1)
		return
	}
	a.s.st.toPeer.Add(1)
}

// readLoop relays datagrams arriving on the relayed address to the client.
func (a *allocation) readLoop() {
	defer a.s.wg.Done()
	size := a.s.cfg.RelayBufSize
	// 4 bytes of ChannelData header in front, padding room behind.
	buf := make([]byte, 4+size+4)
	var out []byte
	stream := a.tr.isStream()
	failures := 0
	for {
		n, src, err := a.relay.ReadFromUDPAddrPort(buf[4 : 4+size])
		if err != nil {
			// Closed by expiry, Refresh 0, or Close. Anything else (Windows
			// reports an ICMP port-unreachable as a read error) is skipped,
			// bounded so a persistent error cannot spin.
			if errors.Is(err, net.ErrClosed) || failures >= 100 {
				return
			}
			failures++
			continue
		}
		failures = 0
		src = ap(src)
		if n == size { // possibly truncated: refuse rather than relay a prefix
			a.s.st.dropped.Add(1)
			continue
		}
		now := a.s.cfg.Now()
		a.mu.Lock()
		ok := a.permittedLocked(src.Addr(), now) && a.rate.allow(n, now)
		var ch *channel
		if ok {
			if c := a.byPeer[src]; c != nil && now.Before(c.expires) {
				ch = c
			}
		}
		a.mu.Unlock()
		if !ok {
			a.s.st.dropped.Add(1)
			continue
		}
		var frame []byte
		if ch != nil {
			binary.BigEndian.PutUint16(buf[0:], ch.number)
			binary.BigEndian.PutUint16(buf[2:], uint16(n))
			end := 4 + n
			if stream {
				for ; end%4 != 0; end++ {
					buf[end] = 0
				}
			}
			frame = buf[:end]
		} else {
			var tx stun.TxID
			binary.BigEndian.PutUint64(tx[0:], rand.Uint64())
			binary.BigEndian.PutUint32(tx[8:], rand.Uint32())
			out = stun.AppendDataIndication(out[:0], tx, src, buf[4:4+n])
			frame = out
		}
		if err := a.tr.send(a.client, frame); err != nil {
			a.s.st.dropped.Add(1)
			continue
		}
		a.s.st.toClient.Add(1)
	}
}
