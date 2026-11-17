package stun

import (
	"bytes"
	"testing"
)

// FuzzDecode feeds arbitrary bytes to Decode and every typed accessor. The
// committed corpus under testdata/fuzz/FuzzDecode is replayed by go test.
func FuzzDecode(f *testing.F) {
	f.Add(unhex(f, vecRequest))
	f.Add(unhex(f, vecIPv4))
	f.Add(unhex(f, vecIPv6))
	f.Add(unhex(f, vecLongTerm))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Decode(b)
		if err != nil {
			return
		}
		if len(m.Attrs) > MaxAttributes {
			t.Fatalf("%d attributes", len(m.Attrs))
		}
		_ = m.CheckIntegrity([]byte("k"))
		_ = m.CheckIntegritySHA256([]byte("k"))
		_ = m.CheckFingerprint()
		_, _ = m.Addr(AttrXORMappedAddress)
		_, _ = m.Addrs(AttrXORPeerAddress)
		_, _ = m.Addr(AttrMappedAddress)
		_, _ = m.Uint32(AttrLifetime)
		_, _, _ = m.ErrorCode()
		_, _ = m.UnknownAttributes()
		_, _ = m.ChannelNumber()
		_, _ = m.RequestedTransport()
		_, _ = m.RequestedAddressFamily()
		_, _ = m.EvenPort()
		_, _ = m.AddressErrorCode()
		_, _ = m.ICMP()
		_, _ = m.PasswordAlgorithms()
		_, _ = m.PasswordAlgorithm()
		// A decoded message re-encodes and decodes to the same attributes
		// (integrity and fingerprint are dropped, padding normalised).
		re := &Message{Class: m.Class, Method: m.Method, TxID: m.TxID}
		n := 0
		for _, a := range m.Attrs {
			switch a.Type {
			case AttrMessageIntegrity, AttrMessageIntegritySHA256, AttrFingerprint:
				continue
			}
			re.Add(a.Type, a.Value)
			n++
		}
		if n > MaxAttributes-3 {
			return
		}
		raw, err := re.Encode()
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		d, err := Decode(raw)
		if err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if len(d.Attrs) != n || d.TxID != m.TxID || d.Class != m.Class || d.Method != m.Method {
			t.Fatal("round trip changed the message")
		}
	})
}

// FuzzChannelData fuzzes the ChannelData codec and the stream framer.
func FuzzChannelData(f *testing.F) {
	f.Add([]byte{0x40, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o', 0, 0, 0})
	f.Add([]byte{0x40, 0x01, 0x00, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if cd, err := DecodeChannelData(b); err == nil {
			if cd.Number < ChannelMin || cd.Number > ChannelMax {
				t.Fatal("channel out of range accepted")
			}
			for _, pad := range []bool{false, true} {
				back, err := DecodeChannelData(cd.AppendTo(nil, pad))
				if err != nil || back.Number != cd.Number || !bytes.Equal(back.Data, cd.Data) {
					t.Fatalf("round trip pad=%v: %v", pad, err)
				}
			}
		}
		fr, _, err := ReadFrame(bytes.NewReader(b), nil)
		if err == nil && len(fr) > MaxMessageSize+4 {
			t.Fatal("frame beyond bound")
		}
	})
}
