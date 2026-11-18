// Package stun implements the STUN message codec of RFC 8489 and the TURN
// attributes and ChannelData framing of RFC 8656.
//
// Decoding is strict and bounded: a message whose length overruns the buffer,
// whose framing is not 4-aligned, or that carries more than MaxAttributes
// attributes is refused. Decoded attribute values alias the input buffer; copy
// them if the buffer is reused.
package stun

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// Wire constants (RFC 8489 section 5).
const (
	MagicCookie uint32 = 0x2112A442
	HeaderSize         = 20
	// MaxAttributes bounds the attributes of one message.
	MaxAttributes = 64
	// MaxMessageSize is the largest message the 16-bit length field can
	// describe (a multiple of 4), header included.
	MaxMessageSize = HeaderSize + 65532

	fingerprintXOR uint32 = 0x5354554e
)

// Errors returned by Decode and the checks.
var (
	ErrShort             = errors.New("stun: message shorter than the 20-byte header")
	ErrBadHeader         = errors.New("stun: top two bits of the message type are not zero")
	ErrBadCookie         = errors.New("stun: bad magic cookie")
	ErrUnaligned         = errors.New("stun: message length is not a multiple of 4")
	ErrBadLength         = errors.New("stun: message length does not match the datagram")
	ErrAttrOverrun       = errors.New("stun: attribute overruns the message")
	ErrTooManyAttributes = errors.New("stun: too many attributes")
	ErrNoAttribute       = errors.New("stun: attribute missing")
	ErrBadAttribute      = errors.New("stun: malformed attribute value")
	ErrIntegrity         = errors.New("stun: integrity check failed")
	ErrFingerprint       = errors.New("stun: fingerprint check failed")
	ErrTooLarge          = errors.New("stun: message too large to encode")
)

// Class is the STUN message class.
type Class uint8

// Message classes.
const (
	ClassRequest    Class = 0
	ClassIndication Class = 1
	ClassSuccess    Class = 2
	ClassError      Class = 3
)

// Method is the 12-bit STUN method.
type Method uint16

// Methods of RFC 8489 and RFC 8656 (section 22, Table 4).
const (
	MethodBinding          Method = 0x001
	MethodAllocate         Method = 0x003
	MethodRefresh          Method = 0x004
	MethodSend             Method = 0x006
	MethodData             Method = 0x007
	MethodCreatePermission Method = 0x008
	MethodChannelBind      Method = 0x009
)

// TxID is the 96-bit transaction ID.
type TxID [12]byte

// NewTxID returns a random transaction ID.
func NewTxID() TxID {
	var t TxID
	if _, err := rand.Read(t[:]); err != nil {
		panic("stun: crypto/rand: " + err.Error())
	}
	return t
}

// Attribute is one type-length-value attribute. Value excludes padding.
type Attribute struct {
	Type  AttrType
	Value []byte
	off   int // offset of the attribute header in the decoded message
}

// Message is a STUN message. The integrity and fingerprint attributes are not
// kept in Attrs when encoding: request them with SetIntegrity,
// SetIntegritySHA256 and SetFingerprint.
type Message struct {
	Class  Class
	Method Method
	TxID   TxID
	Attrs  []Attribute
	// Pad is the byte used to pad attribute values when encoding (zero by
	// default; RFC 5769 vectors pad with spaces).
	Pad byte
	// Received is when a server took the message off the wire, in Unix
	// nanoseconds (an int64, not a time.Time: 8 bytes keep the decoded Message
	// in its size class on the relay's Send path). It is set only when the
	// server has an Observer (one clock read) and is never encoded.
	Received int64

	raw          []byte
	intKey       []byte
	int256Key    []byte
	int256Len    int
	fingerprint  bool
	miIdx, m2Idx int // decoded: index of first MESSAGE-INTEGRITY(-SHA256), or -1
	hasIdx       bool
}

// New returns a message of the given class and method with a fresh TxID.
func New(c Class, m Method) *Message {
	return &Message{Class: c, Method: m, TxID: NewTxID()}
}

func encodeType(c Class, m Method) uint16 {
	mm := uint16(m)
	return mm&0xf | (mm&0x70)<<1 | (mm&0xf80)<<2 | uint16(c&1)<<4 | uint16(c&2)<<7
}

func decodeType(t uint16) (Class, Method) {
	return Class((t>>4)&1 | (t>>7)&2), Method(t&0xf | (t>>1)&0x70 | (t>>2)&0xf80)
}

// IsMessage reports whether b looks like a STUN message (first two bits zero
// and the magic cookie in place), the demultiplexing test of RFC 8656 12.4.
func IsMessage(b []byte) bool {
	return len(b) >= HeaderSize && b[0]>>6 == 0 && binary.BigEndian.Uint32(b[4:8]) == MagicCookie
}

// Decode parses one STUN message occupying exactly b. The result aliases b.
func Decode(b []byte) (*Message, error) {
	if len(b) < HeaderSize {
		return nil, ErrShort
	}
	if b[0]>>6 != 0 {
		return nil, ErrBadHeader
	}
	if binary.BigEndian.Uint32(b[4:8]) != MagicCookie {
		return nil, ErrBadCookie
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n%4 != 0 {
		return nil, ErrUnaligned
	}
	if n != len(b)-HeaderSize {
		return nil, ErrBadLength
	}
	m := &Message{raw: b, miIdx: -1, m2Idx: -1}
	m.Class, m.Method = decodeType(binary.BigEndian.Uint16(b[0:2]))
	copy(m.TxID[:], b[8:20])
	pos := HeaderSize
	for pos < len(b) {
		if len(b)-pos < 4 {
			return nil, ErrAttrOverrun
		}
		if len(m.Attrs) == MaxAttributes {
			return nil, ErrTooManyAttributes
		}
		t := AttrType(binary.BigEndian.Uint16(b[pos:]))
		l := int(binary.BigEndian.Uint16(b[pos+2:]))
		padded := (l + 3) &^ 3
		if padded > len(b)-pos-4 {
			return nil, ErrAttrOverrun
		}
		v := b[pos+4 : pos+4+l : pos+4+l]
		switch t {
		case AttrMessageIntegrity:
			if m.miIdx < 0 {
				m.miIdx = len(m.Attrs)
			}
		case AttrMessageIntegritySHA256:
			if m.m2Idx < 0 {
				m.m2Idx = len(m.Attrs)
			}
		}
		m.Attrs = append(m.Attrs, Attribute{Type: t, Value: v, off: pos})
		pos += 4 + padded
	}
	m.hasIdx = true
	return m, nil
}

// Raw returns the bytes the message was decoded from (nil if built).
func (m *Message) Raw() []byte { return m.raw }

// visible reports whether attribute i may be used: RFC 8489 14.5 and 14.6 say
// attributes after MESSAGE-INTEGRITY are ignored, except MESSAGE-INTEGRITY-SHA256
// and FINGERPRINT; after MESSAGE-INTEGRITY-SHA256 only FINGERPRINT counts.
func (m *Message) visible(i int) bool {
	if !m.hasIdx {
		return true
	}
	t := m.Attrs[i].Type
	if t == AttrFingerprint {
		return true
	}
	if m.miIdx >= 0 && i > m.miIdx && !(t == AttrMessageIntegritySHA256) {
		return false
	}
	if m.m2Idx >= 0 && i > m.m2Idx {
		return false
	}
	return true
}

// Each calls f for every usable attribute, in order (attributes that RFC 8489
// 14.5/14.6 say to ignore are skipped).
func (m *Message) Each(f func(Attribute)) {
	for i := range m.Attrs {
		if m.visible(i) {
			f(m.Attrs[i])
		}
	}
}

// Get returns the first usable attribute of type t.
func (m *Message) Get(t AttrType) ([]byte, bool) {
	for i := range m.Attrs {
		if m.Attrs[i].Type == t && m.visible(i) {
			return m.Attrs[i].Value, true
		}
	}
	return nil, false
}

// GetAll returns every usable attribute of type t, in order.
func (m *Message) GetAll(t AttrType) [][]byte {
	var out [][]byte
	for i := range m.Attrs {
		if m.Attrs[i].Type == t && m.visible(i) {
			out = append(out, m.Attrs[i].Value)
		}
	}
	return out
}

// Add appends an attribute (the value is not copied).
func (m *Message) Add(t AttrType, v []byte) {
	m.Attrs = append(m.Attrs, Attribute{Type: t, Value: v})
}

// SetIntegrity makes Encode append MESSAGE-INTEGRITY (HMAC-SHA1) with key.
func (m *Message) SetIntegrity(key []byte) { m.intKey = key }

// SetIntegritySHA256 makes Encode append MESSAGE-INTEGRITY-SHA256 with key,
// truncated to size bytes (16..32, multiple of 4; 0 means 32).
func (m *Message) SetIntegritySHA256(key []byte, size int) {
	if size == 0 {
		size = 32
	}
	m.int256Key, m.int256Len = key, size
}

// SetFingerprint makes Encode append FINGERPRINT as the last attribute.
func (m *Message) SetFingerprint() { m.fingerprint = true }

func putLen(b []byte, n int) { binary.BigEndian.PutUint16(b[2:4], uint16(n)) }

// AppendTo encodes the message, appending to dst.
func (m *Message) AppendTo(dst []byte) ([]byte, error) {
	start := len(dst)
	var hdr [HeaderSize]byte
	binary.BigEndian.PutUint16(hdr[0:2], encodeType(m.Class, m.Method))
	binary.BigEndian.PutUint32(hdr[4:8], MagicCookie)
	copy(hdr[8:], m.TxID[:])
	dst = append(dst, hdr[:]...)
	count := 0
	for _, a := range m.Attrs {
		switch a.Type {
		case AttrMessageIntegrity, AttrMessageIntegritySHA256, AttrFingerprint:
			continue
		}
		if len(a.Value) > 65535 {
			return dst[:start], ErrTooLarge
		}
		count++
		dst = appendAttr(dst, a.Type, a.Value, m.Pad)
	}
	if count > MaxAttributes-3 {
		return dst[:start], ErrTooManyAttributes
	}
	body := func() int { return len(dst) - start - HeaderSize }
	if m.intKey != nil {
		putLen(dst[start:], body()+24)
		mac := hmac.New(sha1.New, m.intKey)
		mac.Write(dst[start:])
		dst = appendAttr(dst, AttrMessageIntegrity, mac.Sum(nil), 0)
	}
	if m.int256Key != nil {
		if m.int256Len < 16 || m.int256Len > 32 || m.int256Len%4 != 0 {
			return dst[:start], ErrBadAttribute
		}
		putLen(dst[start:], body()+4+m.int256Len)
		mac := hmac.New(sha256.New, m.int256Key)
		mac.Write(dst[start:])
		dst = appendAttr(dst, AttrMessageIntegritySHA256, mac.Sum(nil)[:m.int256Len], 0)
	}
	if m.fingerprint {
		putLen(dst[start:], body()+8)
		var f [4]byte
		binary.BigEndian.PutUint32(f[:], crc32.ChecksumIEEE(dst[start:])^fingerprintXOR)
		dst = appendAttr(dst, AttrFingerprint, f[:], 0)
	}
	if body() > 65532 {
		return dst[:start], ErrTooLarge
	}
	putLen(dst[start:], body())
	return dst, nil
}

// Encode returns the wire form of the message.
func (m *Message) Encode() ([]byte, error) { return m.AppendTo(nil) }

func appendAttr(dst []byte, t AttrType, v []byte, pad byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(t))
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(v)))
	dst = append(dst, v...)
	for i := len(v); i%4 != 0; i++ {
		dst = append(dst, pad)
	}
	return dst
}

// macOver feeds raw[:off] with the length field replaced by n to w.
func (m *Message) lenPatched(off, n int) (head [4]byte, rest []byte) {
	copy(head[:], m.raw[:4])
	binary.BigEndian.PutUint16(head[2:], uint16(n))
	return head, m.raw[4:off]
}

func (m *Message) findAttr(t AttrType) (Attribute, bool) {
	for _, a := range m.Attrs {
		if a.Type == t {
			return a, true
		}
	}
	return Attribute{}, false
}

// CheckIntegrity verifies MESSAGE-INTEGRITY (HMAC-SHA1, RFC 8489 14.5).
func (m *Message) CheckIntegrity(key []byte) error {
	a, ok := m.findAttr(AttrMessageIntegrity)
	if m.raw == nil || !ok || len(a.Value) != 20 {
		return ErrIntegrity
	}
	head, rest := m.lenPatched(a.off, a.off-HeaderSize+24)
	mac := hmac.New(sha1.New, key)
	mac.Write(head[:])
	mac.Write(rest)
	if !hmac.Equal(mac.Sum(nil), a.Value) {
		return ErrIntegrity
	}
	return nil
}

// CheckIntegritySHA256 verifies MESSAGE-INTEGRITY-SHA256 (RFC 8489 14.6).
func (m *Message) CheckIntegritySHA256(key []byte) error {
	a, ok := m.findAttr(AttrMessageIntegritySHA256)
	if m.raw == nil || !ok {
		return ErrIntegrity
	}
	n := len(a.Value)
	if n < 16 || n > 32 || n%4 != 0 {
		return ErrIntegrity
	}
	head, rest := m.lenPatched(a.off, a.off-HeaderSize+4+n)
	mac := hmac.New(sha256.New, key)
	mac.Write(head[:])
	mac.Write(rest)
	if !hmac.Equal(mac.Sum(nil)[:n], a.Value) {
		return ErrIntegrity
	}
	return nil
}

// CheckFingerprint verifies FINGERPRINT (RFC 8489 14.7); it must be last.
func (m *Message) CheckFingerprint() error {
	if m.raw == nil || len(m.Attrs) == 0 {
		return ErrFingerprint
	}
	a := m.Attrs[len(m.Attrs)-1]
	if a.Type != AttrFingerprint || len(a.Value) != 4 {
		return ErrFingerprint
	}
	head, rest := m.lenPatched(a.off, a.off-HeaderSize+8)
	crc := crc32.Update(0, crc32.IEEETable, head[:])
	crc = crc32.Update(crc, crc32.IEEETable, rest)
	if crc^fingerprintXOR != binary.BigEndian.Uint32(a.Value) {
		return ErrFingerprint
	}
	return nil
}
