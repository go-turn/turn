package stun

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestAppendDataIndication(t *testing.T) {
	for _, peer := range []string{"192.0.2.9:4000", "[2001:db8::1]:5"} {
		for _, n := range []int{0, 1, 5, 1200} {
			data := bytes.Repeat([]byte{7}, n)
			tx := NewTxID()
			ap := netip.MustParseAddrPort(peer)
			raw := AppendDataIndication([]byte("pre"), tx, ap, data)[3:]
			m, err := Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if m.Class != ClassIndication || m.Method != MethodData || m.TxID != tx {
				t.Fatalf("header %v %v", m.Class, m.Method)
			}
			got, err := m.Addr(AttrXORPeerAddress)
			if err != nil || got != ap {
				t.Fatalf("peer %v %v", got, err)
			}
			if d, _ := m.Get(AttrData); !bytes.Equal(d, data) {
				t.Fatal("data")
			}
		}
	}
}

func TestEachSkipsIgnored(t *testing.T) {
	m := New(ClassRequest, MethodBinding)
	m.AddString(AttrUsername, "a")
	m.SetIntegrity([]byte("k"))
	raw := m.mustEncode(t)
	raw = append(raw, 0, 0x30, 0, 0)
	raw[3] += 4
	d, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	var seen []AttrType
	d.Each(func(a Attribute) { seen = append(seen, a.Type) })
	if len(seen) != 2 || seen[1] != AttrMessageIntegrity {
		t.Fatal(seen)
	}
}
