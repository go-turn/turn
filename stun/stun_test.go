package stun

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// Vectors copied from RFC 5769 sections 2.1-2.4.
const (
	rfc5769Password = "VOkJxbRl1RmTxUk/WvJxBt"

	vecRequest = `00010058 2112a442 b7e7a701 bc34d686 fa87dfae 80220010 5354554e 20746573
7420636c 69656e74 00240004 6e0001ff 80290008 932ff9b1 51263b36 00060009
6576746a 3a683676 59202020 00080014 9aeaa70c bfd8cb56 781ef2b5 b2d3f249
c1b571a2 80280004 e57a3bcf`

	vecIPv4 = `0101003c 2112a442 b7e7a701 bc34d686 fa87dfae 8022000b 74657374 20766563
746f7220 00200008 0001a147 e112a643 00080014 2b91f599 fd9e90c3 8c7489f9
2af9ba53 f06be7d7 80280004 c07d4c96`

	vecIPv6 = `010100 48 2112a442 b7e7a701 bc34d686 fa87dfae 8022000b 74657374 20766563
746f7220 00200014 0002a147 0113a9fa a5d3f179 bc25f4b5 bed2b9d9 00080014
a382954e 4be67bf1 1784c97c 8292c275 bfe3ed41 80280004 c8fb0b4c`

	vecLongTerm = `00010060 2112a442 78ad3433 c6ad72c0 29da412e 00060012 e3839ee3 8388e383
aae38383 e382afe3 82b90000 0015001c 662f2f34 39396b39 35346436 4f4c3334
6f4c3946 53547679 36347341 00140 00b 6578616d 706c652e 6f726700 00080014
f6702465 6dd64a3e 02b8e071 2e85c9a2 8ca89666`
)

func (m *Message) mustEncode(t testing.TB) []byte {
	t.Helper()
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRFC5769SampleRequest(t *testing.T) {
	raw := unhex(t, vecRequest)
	m, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Class != ClassRequest || m.Method != MethodBinding {
		t.Fatalf("type %v %v", m.Class, m.Method)
	}
	if u, _ := m.String(AttrUsername); u != "evtj:h6vY" {
		t.Fatalf("username %q", u)
	}
	if s, _ := m.String(AttrSoftware); s != "STUN test client" {
		t.Fatalf("software %q", s)
	}
	if err := m.CheckIntegrity([]byte(rfc5769Password)); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckIntegrity([]byte("wrong")); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong key accepted: %v", err)
	}
	if err := m.CheckFingerprint(); err != nil {
		t.Fatal(err)
	}
	// Re-encode with the vector's space padding: byte-identical.
	re := &Message{Class: m.Class, Method: m.Method, TxID: m.TxID, Pad: ' '}
	for _, a := range m.Attrs {
		re.Add(a.Type, a.Value)
	}
	got, err := re.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// The vector's integrity/fingerprint are over the original attributes.
	re.SetIntegrity([]byte(rfc5769Password))
	re.SetFingerprint()
	got, err = re.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("re-encode differs:\n%x\n%x", got, raw)
	}
}

func TestRFC5769Responses(t *testing.T) {
	cases := []struct {
		name string
		vec  string
		want string
	}{
		{"ipv4", vecIPv4, "192.0.2.1:32853"},
		{"ipv6", vecIPv6, "[2001:db8:1234:5678:11:2233:4455:6677]:32853"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := unhex(t, c.vec)
			m, err := Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if m.Class != ClassSuccess || m.Method != MethodBinding {
				t.Fatalf("type %v %v", m.Class, m.Method)
			}
			ap, err := m.Addr(AttrXORMappedAddress)
			if err != nil || ap != netip.MustParseAddrPort(c.want) {
				t.Fatalf("addr %v %v", ap, err)
			}
			if err := m.CheckIntegrity([]byte(rfc5769Password)); err != nil {
				t.Fatal(err)
			}
			if err := m.CheckFingerprint(); err != nil {
				t.Fatal(err)
			}
			re := &Message{Class: ClassSuccess, Method: MethodBinding, TxID: m.TxID, Pad: ' '}
			re.AddString(AttrSoftware, "test vector")
			re.AddAddr(AttrXORMappedAddress, ap)
			re.SetIntegrity([]byte(rfc5769Password))
			re.SetFingerprint()
			got, err := re.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, raw) {
				t.Fatalf("re-encode differs:\n%x\n%x", got, raw)
			}
		})
	}
}

func TestRFC5769LongTermRequest(t *testing.T) {
	raw := unhex(t, vecLongTerm)
	m, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	user := "マトリックス"
	if u, _ := m.String(AttrUsername); u != user {
		t.Fatalf("username %q", u)
	}
	if r, _ := m.String(AttrRealm); r != "example.org" {
		t.Fatalf("realm %q", r)
	}
	// Password after SASLprep: TheMatrIX.
	key := LongTermKeyMD5(user, "example.org", "TheMatrIX")
	if err := m.CheckIntegrity(key); err != nil {
		t.Fatal(err)
	}
	nonce, _ := m.String(AttrNonce)
	re := &Message{Class: ClassRequest, Method: MethodBinding, TxID: m.TxID}
	re.AddString(AttrUsername, user)
	re.AddString(AttrNonce, nonce)
	re.AddString(AttrRealm, "example.org")
	re.SetIntegrity(key)
	got, err := re.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("re-encode differs:\n%x\n%x", got, raw)
	}
}

func TestIntegritySHA256RoundTrip(t *testing.T) {
	key := LongTermKeySHA256("alice", "example.org", "pw")
	if len(key) != 32 || len(UserHash("alice", "example.org")) != 32 {
		t.Fatal("key length")
	}
	for _, size := range []int{0, 16, 20, 32} {
		m := New(ClassRequest, MethodAllocate)
		m.AddString(AttrUsername, "alice")
		m.SetIntegrity([]byte("sha1key"))
		m.SetIntegritySHA256(key, size)
		m.SetFingerprint()
		raw, err := m.Encode()
		if err != nil {
			t.Fatal(err)
		}
		d, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.CheckIntegrity([]byte("sha1key")); err != nil {
			t.Fatal(err)
		}
		if err := d.CheckIntegritySHA256(key); err != nil {
			t.Fatal(err)
		}
		if err := d.CheckIntegritySHA256([]byte("x")); err == nil {
			t.Fatal("wrong key accepted")
		}
		if err := d.CheckFingerprint(); err != nil {
			t.Fatal(err)
		}
		// Flip one byte of the username: integrity must fail.
		bad := bytes.Clone(raw)
		bad[HeaderSize+4] ^= 1
		db, _ := Decode(bad)
		if db.CheckIntegritySHA256(key) == nil || db.CheckIntegrity([]byte("sha1key")) == nil {
			t.Fatal("tampered message accepted")
		}
	}
	m := New(ClassRequest, MethodAllocate)
	m.SetIntegritySHA256(key, 18)
	if _, err := m.Encode(); err == nil {
		t.Fatal("size 18 accepted")
	}
}

func TestKeyDerivationKnown(t *testing.T) {
	// RFC 8489 section 9.2.2 example: "user:realm:pass".
	if got := hex.EncodeToString(LongTermKeyMD5("user", "realm", "pass")); got != "8493fbc53ba582fb4c044c456bdc40eb" {
		t.Fatal(got)
	}
}

func TestAttributesAfterIntegrityIgnored(t *testing.T) {
	m := New(ClassRequest, MethodBinding)
	m.AddString(AttrUsername, "alice")
	m.SetIntegrity([]byte("k"))
	raw, _ := m.Encode()
	// Append an attacker attribute after MESSAGE-INTEGRITY.
	raw = append(raw, 0x80, 0x22, 0, 4, 'e', 'v', 'i', 'l')
	binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)-HeaderSize))
	d, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Get(AttrSoftware); ok {
		t.Fatal("attribute after MESSAGE-INTEGRITY is visible")
	}
	if _, ok := d.Get(AttrUsername); !ok {
		t.Fatal("username lost")
	}
}

func TestDecodeRefusals(t *testing.T) {
	good := unhex(t, vecIPv4)
	mut := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(good)) }
	tooMany := New(ClassRequest, MethodBinding)
	for i := 0; i < MaxAttributes+1; i++ {
		tooMany.Add(AttrSoftware, nil)
	}
	over := (&Message{Class: ClassRequest, Method: MethodBinding}).mustEncode(t)
	for i := 0; i < MaxAttributes+1; i++ {
		over = append(over, 0x80, 0x22, 0, 0)
	}
	binary.BigEndian.PutUint16(over[2:], uint16(len(over)-HeaderSize))
	atLimit := bytes.Clone(over[:HeaderSize+4*MaxAttributes])
	binary.BigEndian.PutUint16(atLimit[2:], uint16(len(atLimit)-HeaderSize))
	if _, err := Decode(atLimit); err != nil {
		t.Fatalf("exactly MaxAttributes refused: %v", err)
	}

	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"short", good[:19], ErrShort},
		{"top bits", mut(func(b []byte) []byte { b[0] |= 0x40; return b }), ErrBadHeader},
		{"cookie", mut(func(b []byte) []byte { b[4] ^= 1; return b }), ErrBadCookie},
		{"unaligned length", mut(func(b []byte) []byte { b[3] = 0x3d; return b }), ErrUnaligned},
		{"length overruns", mut(func(b []byte) []byte { b[3] = 0x40; return b }), ErrBadLength},
		{"trailing bytes", append(bytes.Clone(good), 0, 0, 0, 0), ErrBadLength},
		{"truncated datagram", good[:len(good)-4], ErrBadLength},
		{"attr overruns", mut(func(b []byte) []byte { b[HeaderSize+3] = 0xf0; return b }), ErrAttrOverrun},
		{"too many attributes", over, ErrTooManyAttributes},
	}
	for _, c := range cases {
		if _, err := Decode(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	// A trailing 1-3 byte tail inside the length: attribute header overruns.
	tail := mut(func(b []byte) []byte { return append(b[:len(b):len(b)], 0, 0, 0, 0) })
	binary.BigEndian.PutUint16(tail[2:], uint16(len(tail)-HeaderSize))
	if _, err := Decode(tail); err != nil {
		t.Fatalf("zero-length attribute of type 0: %v", err)
	}
	// Encode refuses too many attributes.
	if _, err := tooMany.Encode(); !errors.Is(err, ErrTooManyAttributes) {
		t.Fatalf("encode: %v", err)
	}
}

func TestTypedAttributes(t *testing.T) {
	m := New(ClassRequest, MethodAllocate)
	m.AddUint32(AttrLifetime, 600)
	m.AddChannelNumber(0x4001)
	m.AddRequestedTransport(17)
	m.AddRequestedAddressFamily(FamilyIPv6)
	m.AddEvenPort(EvenPort{Reserve: true})
	m.AddError(CodeStaleNonce, "Stale Nonce")
	m.AddUnknownAttributes([]AttrType{0x0030, 0x0031})
	m.AddAddressErrorCode(AddressErrorCode{Family: FamilyIPv6, Code: 440, Reason: "no"})
	m.AddICMP(ICMP{Type: 3, Code: 4, Data: 1280})
	m.AddPasswordAlgorithms([]PasswordAlgorithm{{AlgSHA256, nil}, {AlgMD5, []byte{1}}})
	m.AddPasswordAlgorithm(PasswordAlgorithm{Algorithm: AlgSHA256})
	m.AddAddr(AttrXORPeerAddress, netip.MustParseAddrPort("[::ffff:1.2.3.4]:99"))
	raw, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := d.Uint32(AttrLifetime); v != 600 {
		t.Fatal(v)
	}
	if n, _ := d.ChannelNumber(); n != 0x4001 {
		t.Fatal(n)
	}
	if p, _ := d.RequestedTransport(); p != 17 {
		t.Fatal(p)
	}
	if f, _ := d.RequestedAddressFamily(); f != FamilyIPv6 {
		t.Fatal(f)
	}
	if e, _ := d.EvenPort(); !e.Reserve {
		t.Fatal(e)
	}
	if c, r, err := d.ErrorCode(); err != nil || c != 438 || r != "Stale Nonce" {
		t.Fatal(c, r, err)
	}
	if u, _ := d.UnknownAttributes(); len(u) != 2 || u[1] != 0x31 {
		t.Fatal(u)
	}
	if a, err := d.AddressErrorCode(); err != nil || a.Code != 440 || a.Family != FamilyIPv6 {
		t.Fatal(a, err)
	}
	if i, _ := d.ICMP(); i.Data != 1280 || i.Type != 3 {
		t.Fatal(i)
	}
	if as, err := d.PasswordAlgorithms(); err != nil || len(as) != 2 || as[1].Params[0] != 1 {
		t.Fatal(as, err)
	}
	if a, err := d.PasswordAlgorithm(); err != nil || a.Algorithm != AlgSHA256 {
		t.Fatal(a, err)
	}
	if ap, _ := d.Addr(AttrXORPeerAddress); ap.Addr().Unmap() != netip.MustParseAddr("1.2.3.4") || ap.Port() != 99 {
		t.Fatal(ap)
	}
	// Malformed values are refused, not panicked on.
	bad := New(ClassRequest, MethodAllocate)
	bad.Add(AttrErrorCode, []byte{0, 0, 9, 0})
	bad.Add(AttrChannelNumber, []byte{1})
	bad.Add(AttrXORPeerAddress, []byte{0, 1, 0, 0, 1})
	bad.Add(AttrPasswordAlgorithms, []byte{0, 2, 0, 9})
	bad.Add(AttrRequestedAddressFamily, []byte{7, 0, 0, 0})
	if _, _, err := bad.ErrorCode(); err == nil {
		t.Fatal("bad error class")
	}
	if _, err := bad.ChannelNumber(); err == nil {
		t.Fatal("bad channel")
	}
	if _, err := bad.Addr(AttrXORPeerAddress); err == nil {
		t.Fatal("bad addr")
	}
	if _, err := bad.PasswordAlgorithms(); err == nil {
		t.Fatal("bad algs")
	}
	if _, err := bad.RequestedAddressFamily(); err == nil {
		t.Fatal("bad family")
	}
	if _, err := bad.Uint32(AttrLifetime); !errors.Is(err, ErrNoAttribute) {
		t.Fatal(err)
	}
}

func TestMessageTypeBits(t *testing.T) {
	for _, m := range []Method{MethodBinding, MethodAllocate, MethodRefresh, MethodSend, MethodData, MethodCreatePermission, MethodChannelBind, 0xfff} {
		for c := ClassRequest; c <= ClassError; c++ {
			gc, gm := decodeType(encodeType(c, m))
			if gc != c || gm != m {
				t.Fatalf("%v %v -> %v %v", c, m, gc, gm)
			}
		}
	}
	if encodeType(ClassSuccess, MethodBinding) != 0x0101 || encodeType(ClassError, MethodAllocate) != 0x0113 ||
		encodeType(ClassIndication, MethodSend) != 0x0016 {
		t.Fatal("known type codes")
	}
}

func TestChannelData(t *testing.T) {
	cd := ChannelData{Number: 0x4000, Data: []byte("hello")}
	for _, pad := range []bool{false, true} {
		raw := cd.AppendTo(nil, pad)
		if pad && len(raw) != 12 || !pad && len(raw) != 9 {
			t.Fatalf("pad=%v len %d", pad, len(raw))
		}
		got, err := DecodeChannelData(raw)
		if err != nil || got.Number != 0x4000 || string(got.Data) != "hello" {
			t.Fatal(got, err)
		}
	}
	empty, err := DecodeChannelData([]byte{0x40, 1, 0, 0})
	if err != nil || len(empty.Data) != 0 {
		t.Fatal(empty, err)
	}
	bad := []struct {
		name string
		in   []byte
		want error
	}{
		{"short", []byte{0x40, 0, 0}, ErrShort},
		{"channel 0x3fff", []byte{0x3f, 0xff, 0, 0}, ErrBadChannel},
		{"channel 0x5000", []byte{0x50, 0, 0, 0}, ErrBadChannel},
		{"overrun", []byte{0x40, 0, 0, 9, 1, 2}, ErrBadLength},
		{"garbage tail", []byte{0x40, 0, 0, 1, 1, 0, 0, 0, 0}, ErrBadLength},
	}
	for _, c := range bad {
		if _, err := DecodeChannelData(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestReadFrame(t *testing.T) {
	var stream []byte
	req := New(ClassRequest, MethodBinding)
	req.AddString(AttrSoftware, "x")
	raw, _ := req.Encode()
	stream = append(stream, raw...)
	stream = ChannelData{Number: 0x4001, Data: []byte("abc")}.AppendTo(stream, true)
	r := bytes.NewReader(stream)
	var buf []byte
	f, buf, err := ReadFrame(r, buf)
	if err != nil || !IsMessage(f) || !bytes.Equal(f, raw) {
		t.Fatal(err)
	}
	f, buf, err = ReadFrame(r, buf)
	if err != nil || !IsChannelData(f) || len(f) != 8 {
		t.Fatal(err, len(f))
	}
	if _, _, err = ReadFrame(r, buf); err == nil {
		t.Fatal("expected EOF")
	}
	for name, in := range map[string][]byte{
		"junk first byte": {0xff, 0, 0, 0},
		"unaligned":       {0, 1, 0, 3},
		"truncated":       {0x40, 0, 0, 8, 1},
	} {
		if _, _, err := ReadFrame(bytes.NewReader(in), nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
