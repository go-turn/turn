package stun

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"strconv"
)

// AttrType is a STUN attribute type. Types below 0x8000 are
// comprehension-required (RFC 8489 section 14).
type AttrType uint16

// Attribute types: RFC 8489 section 18.3 and RFC 8656 section 22 (Table 5).
const (
	AttrMappedAddress          AttrType = 0x0001
	AttrUsername               AttrType = 0x0006
	AttrMessageIntegrity       AttrType = 0x0008
	AttrErrorCode              AttrType = 0x0009
	AttrUnknownAttributes      AttrType = 0x000A
	AttrChannelNumber          AttrType = 0x000C
	AttrLifetime               AttrType = 0x000D
	AttrXORPeerAddress         AttrType = 0x0012
	AttrData                   AttrType = 0x0013
	AttrRealm                  AttrType = 0x0014
	AttrNonce                  AttrType = 0x0015
	AttrXORRelayedAddress      AttrType = 0x0016
	AttrRequestedAddressFamily AttrType = 0x0017
	AttrEvenPort               AttrType = 0x0018
	AttrRequestedTransport     AttrType = 0x0019
	AttrDontFragment           AttrType = 0x001A
	AttrMessageIntegritySHA256 AttrType = 0x001C
	AttrPasswordAlgorithm      AttrType = 0x001D
	AttrUserhash               AttrType = 0x001E
	AttrXORMappedAddress       AttrType = 0x0020
	AttrReservationToken       AttrType = 0x0022
	AttrAdditionalAddrFamily   AttrType = 0x8000
	AttrAddressErrorCode       AttrType = 0x8001
	AttrPasswordAlgorithms     AttrType = 0x8002
	AttrAlternateDomain        AttrType = 0x8003
	AttrICMP                   AttrType = 0x8004
	AttrSoftware               AttrType = 0x8022
	AttrAlternateServer        AttrType = 0x8023
	AttrFingerprint            AttrType = 0x8028
)

// ComprehensionRequired reports whether t must be understood.
func (t AttrType) ComprehensionRequired() bool { return t < 0x8000 }

var attrNames = map[AttrType]string{
	AttrMappedAddress: "MAPPED-ADDRESS", AttrUsername: "USERNAME", AttrMessageIntegrity: "MESSAGE-INTEGRITY",
	AttrErrorCode: "ERROR-CODE", AttrUnknownAttributes: "UNKNOWN-ATTRIBUTES", AttrChannelNumber: "CHANNEL-NUMBER",
	AttrLifetime: "LIFETIME", AttrXORPeerAddress: "XOR-PEER-ADDRESS", AttrData: "DATA", AttrRealm: "REALM",
	AttrNonce: "NONCE", AttrXORRelayedAddress: "XOR-RELAYED-ADDRESS", AttrRequestedAddressFamily: "REQUESTED-ADDRESS-FAMILY",
	AttrEvenPort: "EVEN-PORT", AttrRequestedTransport: "REQUESTED-TRANSPORT", AttrDontFragment: "DONT-FRAGMENT",
	AttrMessageIntegritySHA256: "MESSAGE-INTEGRITY-SHA256", AttrPasswordAlgorithm: "PASSWORD-ALGORITHM",
	AttrUserhash: "USERHASH", AttrXORMappedAddress: "XOR-MAPPED-ADDRESS", AttrReservationToken: "RESERVATION-TOKEN",
	AttrAdditionalAddrFamily: "ADDITIONAL-ADDRESS-FAMILY", AttrAddressErrorCode: "ADDRESS-ERROR-CODE",
	AttrPasswordAlgorithms: "PASSWORD-ALGORITHMS", AttrAlternateDomain: "ALTERNATE-DOMAIN", AttrICMP: "ICMP",
	AttrSoftware: "SOFTWARE", AttrAlternateServer: "ALTERNATE-SERVER", AttrFingerprint: "FINGERPRINT",
}

func (t AttrType) String() string {
	if s, ok := attrNames[t]; ok {
		return s
	}
	return "0x" + strconv.FormatUint(uint64(t), 16)
}

// Error codes (RFC 8489 section 14.8, RFC 8656 section 21... see the TURN
// registry for 437-508).
const (
	CodeTryAlternate        = 300
	CodeBadRequest          = 400
	CodeUnauthenticated     = 401
	CodeForbidden           = 403
	CodeUnknownAttribute    = 420
	CodeAllocationMismatch  = 437
	CodeStaleNonce          = 438
	CodeAddrFamilyNotSupp   = 440
	CodeWrongCredentials    = 441
	CodeUnsupportedProtocol = 442
	CodePeerAddrFamily      = 443
	CodeAllocQuota          = 486
	CodeServerError         = 500
	CodeInsufficientCap     = 508
)

// Password algorithm numbers (RFC 8489 section 18.5).
const (
	AlgMD5    uint16 = 0x0001
	AlgSHA256 uint16 = 0x0002
)

// Address families as used on the wire.
const (
	FamilyIPv4 = 0x01
	FamilyIPv6 = 0x02
)

// LongTermKeyMD5 is MD5(username ":" realm ":" password), RFC 8489 9.2.2. The
// caller applies the OpaqueString profile (SASLprep) beforehand if needed.
func LongTermKeyMD5(username, realm, password string) []byte {
	s := md5.Sum([]byte(username + ":" + realm + ":" + password))
	return s[:]
}

// LongTermKeySHA256 is SHA-256(username ":" realm ":" password), RFC 8489
// 18.5.1.2.
func LongTermKeySHA256(username, realm, password string) []byte {
	s := sha256.Sum256([]byte(username + ":" + realm + ":" + password))
	return s[:]
}

// UserHash is SHA-256(username ":" realm), RFC 8489 14.4.
func UserHash(username, realm string) []byte {
	s := sha256.Sum256([]byte(username + ":" + realm))
	return s[:]
}

// AppendAddress encodes a (XOR-)MAPPED-ADDRESS style value.
func AppendAddress(dst []byte, ap netip.AddrPort, xor bool, tx TxID) []byte {
	a := ap.Addr()
	port := ap.Port()
	if xor {
		port ^= uint16(MagicCookie >> 16)
	}
	if a.Is4() || a.Is4In6() {
		a4 := a.Unmap().As4()
		if xor {
			c := binary.BigEndian.AppendUint32(nil, MagicCookie)
			for i := range a4 {
				a4[i] ^= c[i]
			}
		}
		dst = append(dst, 0, FamilyIPv4)
		dst = binary.BigEndian.AppendUint16(dst, port)
		return append(dst, a4[:]...)
	}
	a16 := a.As16()
	if xor {
		mask := binary.BigEndian.AppendUint32(nil, MagicCookie)
		mask = append(mask, tx[:]...)
		for i := range a16 {
			a16[i] ^= mask[i]
		}
	}
	dst = append(dst, 0, FamilyIPv6)
	dst = binary.BigEndian.AppendUint16(dst, port)
	return append(dst, a16[:]...)
}

// ParseAddress decodes a (XOR-)MAPPED-ADDRESS style value.
func ParseAddress(v []byte, xor bool, tx TxID) (netip.AddrPort, error) {
	if len(v) < 4 {
		return netip.AddrPort{}, ErrBadAttribute
	}
	port := binary.BigEndian.Uint16(v[2:4])
	if xor {
		port ^= uint16(MagicCookie >> 16)
	}
	switch v[1] {
	case FamilyIPv4:
		if len(v) != 8 {
			return netip.AddrPort{}, ErrBadAttribute
		}
		var a [4]byte
		copy(a[:], v[4:])
		if xor {
			c := binary.BigEndian.AppendUint32(nil, MagicCookie)
			for i := range a {
				a[i] ^= c[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), nil
	case FamilyIPv6:
		if len(v) != 20 {
			return netip.AddrPort{}, ErrBadAttribute
		}
		var a [16]byte
		copy(a[:], v[4:])
		if xor {
			mask := binary.BigEndian.AppendUint32(nil, MagicCookie)
			mask = append(mask, tx[:]...)
			for i := range a {
				a[i] ^= mask[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), nil
	}
	return netip.AddrPort{}, ErrBadAttribute
}

func isXORAddr(t AttrType) bool {
	return t == AttrXORMappedAddress || t == AttrXORPeerAddress || t == AttrXORRelayedAddress
}

// AddAddr adds an address attribute, XOR-encoded for the XOR-* types.
func (m *Message) AddAddr(t AttrType, ap netip.AddrPort) {
	m.Add(t, AppendAddress(nil, ap, isXORAddr(t), m.TxID))
}

// Addr decodes the first address attribute of type t.
func (m *Message) Addr(t AttrType) (netip.AddrPort, error) {
	v, ok := m.Get(t)
	if !ok {
		return netip.AddrPort{}, ErrNoAttribute
	}
	return ParseAddress(v, isXORAddr(t), m.TxID)
}

// Addrs decodes every address attribute of type t.
func (m *Message) Addrs(t AttrType) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, v := range m.GetAll(t) {
		ap, err := ParseAddress(v, isXORAddr(t), m.TxID)
		if err != nil {
			return nil, err
		}
		out = append(out, ap)
	}
	return out, nil
}

// AddUint32 adds a 32-bit attribute (for example LIFETIME).
func (m *Message) AddUint32(t AttrType, v uint32) {
	m.Add(t, binary.BigEndian.AppendUint32(nil, v))
}

// Uint32 decodes a 32-bit attribute.
func (m *Message) Uint32(t AttrType) (uint32, error) {
	v, ok := m.Get(t)
	if !ok {
		return 0, ErrNoAttribute
	}
	if len(v) != 4 {
		return 0, ErrBadAttribute
	}
	return binary.BigEndian.Uint32(v), nil
}

// AddString adds a UTF-8 string attribute.
func (m *Message) AddString(t AttrType, s string) { m.Add(t, []byte(s)) }

// String returns a string attribute.
func (m *Message) String(t AttrType) (string, bool) {
	v, ok := m.Get(t)
	return string(v), ok
}

// AddError adds ERROR-CODE with a reason phrase (RFC 8489 14.8).
func (m *Message) AddError(code int, reason string) {
	if len(reason) > 127 {
		reason = reason[:127]
	}
	v := []byte{0, 0, byte(code / 100), byte(code % 100)}
	m.Add(AttrErrorCode, append(v, reason...))
}

// ErrorCode decodes ERROR-CODE.
func (m *Message) ErrorCode() (code int, reason string, err error) {
	v, ok := m.Get(AttrErrorCode)
	if !ok {
		return 0, "", ErrNoAttribute
	}
	if len(v) < 4 {
		return 0, "", ErrBadAttribute
	}
	class, num := int(v[2]&7), int(v[3])
	if class < 3 || class > 6 || num > 99 {
		return 0, "", ErrBadAttribute
	}
	return class*100 + num, string(v[4:]), nil
}

// AddUnknownAttributes adds UNKNOWN-ATTRIBUTES.
func (m *Message) AddUnknownAttributes(ts []AttrType) {
	var v []byte
	for _, t := range ts {
		v = binary.BigEndian.AppendUint16(v, uint16(t))
	}
	m.Add(AttrUnknownAttributes, v)
}

// UnknownAttributes decodes UNKNOWN-ATTRIBUTES.
func (m *Message) UnknownAttributes() ([]AttrType, error) {
	v, ok := m.Get(AttrUnknownAttributes)
	if !ok {
		return nil, ErrNoAttribute
	}
	if len(v)%2 != 0 {
		return nil, ErrBadAttribute
	}
	out := make([]AttrType, 0, len(v)/2)
	for i := 0; i < len(v); i += 2 {
		out = append(out, AttrType(binary.BigEndian.Uint16(v[i:])))
	}
	return out, nil
}

// AddChannelNumber adds CHANNEL-NUMBER (RFC 8656 18.1).
func (m *Message) AddChannelNumber(n uint16) {
	m.Add(AttrChannelNumber, []byte{byte(n >> 8), byte(n), 0, 0})
}

// ChannelNumber decodes CHANNEL-NUMBER.
func (m *Message) ChannelNumber() (uint16, error) {
	v, ok := m.Get(AttrChannelNumber)
	if !ok {
		return 0, ErrNoAttribute
	}
	if len(v) != 4 {
		return 0, ErrBadAttribute
	}
	return binary.BigEndian.Uint16(v), nil
}

// AddRequestedTransport adds REQUESTED-TRANSPORT (17 is UDP).
func (m *Message) AddRequestedTransport(proto byte) {
	m.Add(AttrRequestedTransport, []byte{proto, 0, 0, 0})
}

// RequestedTransport decodes REQUESTED-TRANSPORT.
func (m *Message) RequestedTransport() (byte, error) {
	v, ok := m.Get(AttrRequestedTransport)
	if !ok {
		return 0, ErrNoAttribute
	}
	if len(v) != 4 {
		return 0, ErrBadAttribute
	}
	return v[0], nil
}

// AddRequestedAddressFamily adds REQUESTED-ADDRESS-FAMILY.
func (m *Message) AddRequestedAddressFamily(f byte) {
	m.Add(AttrRequestedAddressFamily, []byte{f, 0, 0, 0})
}

// RequestedAddressFamily decodes REQUESTED-ADDRESS-FAMILY.
func (m *Message) RequestedAddressFamily() (byte, error) {
	v, ok := m.Get(AttrRequestedAddressFamily)
	if !ok {
		return 0, ErrNoAttribute
	}
	if len(v) != 4 || (v[0] != FamilyIPv4 && v[0] != FamilyIPv6) {
		return 0, ErrBadAttribute
	}
	return v[0], nil
}

// EvenPort is the decoded EVEN-PORT attribute.
type EvenPort struct{ Reserve bool }

// AddEvenPort adds EVEN-PORT (RFC 8656 18.5).
func (m *Message) AddEvenPort(e EvenPort) {
	b := byte(0)
	if e.Reserve {
		b = 0x80
	}
	m.Add(AttrEvenPort, []byte{b})
}

// EvenPort decodes EVEN-PORT.
func (m *Message) EvenPort() (EvenPort, error) {
	v, ok := m.Get(AttrEvenPort)
	if !ok {
		return EvenPort{}, ErrNoAttribute
	}
	if len(v) != 1 {
		return EvenPort{}, ErrBadAttribute
	}
	return EvenPort{Reserve: v[0]&0x80 != 0}, nil
}

// AddAdditionalAddressFamily adds ADDITIONAL-ADDRESS-FAMILY (only IPv6 valid).
func (m *Message) AddAdditionalAddressFamily(f byte) {
	m.Add(AttrAdditionalAddrFamily, []byte{f, 0, 0, 0})
}

// AddressErrorCode is the decoded ADDRESS-ERROR-CODE attribute.
type AddressErrorCode struct {
	Family byte
	Code   int
	Reason string
}

// AddAddressErrorCode adds ADDRESS-ERROR-CODE (RFC 8656 18.10).
func (m *Message) AddAddressErrorCode(e AddressErrorCode) {
	if len(e.Reason) > 127 {
		e.Reason = e.Reason[:127]
	}
	v := []byte{e.Family, 0, byte(e.Code / 100), byte(e.Code % 100)}
	m.Add(AttrAddressErrorCode, append(v, e.Reason...))
}

// AddressErrorCode decodes ADDRESS-ERROR-CODE.
func (m *Message) AddressErrorCode() (AddressErrorCode, error) {
	v, ok := m.Get(AttrAddressErrorCode)
	if !ok {
		return AddressErrorCode{}, ErrNoAttribute
	}
	if len(v) < 4 {
		return AddressErrorCode{}, ErrBadAttribute
	}
	class, num := int(v[2]&7), int(v[3])
	if class < 3 || class > 6 || num > 99 || (v[0] != FamilyIPv4 && v[0] != FamilyIPv6) {
		return AddressErrorCode{}, ErrBadAttribute
	}
	return AddressErrorCode{Family: v[0], Code: class*100 + num, Reason: string(v[4:])}, nil
}

// ICMP is the decoded ICMP attribute (RFC 8656 18.13).
type ICMP struct {
	Type, Code uint8
	Data       uint32
}

// AddICMP adds the ICMP attribute.
func (m *Message) AddICMP(i ICMP) {
	v := []byte{0, 0, i.Type, i.Code}
	m.Add(AttrICMP, binary.BigEndian.AppendUint32(v, i.Data))
}

// ICMP decodes the ICMP attribute.
func (m *Message) ICMP() (ICMP, error) {
	v, ok := m.Get(AttrICMP)
	if !ok {
		return ICMP{}, ErrNoAttribute
	}
	if len(v) != 8 {
		return ICMP{}, ErrBadAttribute
	}
	return ICMP{Type: v[2], Code: v[3], Data: binary.BigEndian.Uint32(v[4:])}, nil
}

// PasswordAlgorithm is one entry of PASSWORD-ALGORITHM(S).
type PasswordAlgorithm struct {
	Algorithm uint16
	Params    []byte
}

func appendAlg(dst []byte, a PasswordAlgorithm) []byte {
	dst = binary.BigEndian.AppendUint16(dst, a.Algorithm)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(a.Params)))
	dst = append(dst, a.Params...)
	for i := len(a.Params); i%4 != 0; i++ {
		dst = append(dst, 0)
	}
	return dst
}

// AddPasswordAlgorithms adds PASSWORD-ALGORITHMS (RFC 8489 14.11).
func (m *Message) AddPasswordAlgorithms(as []PasswordAlgorithm) {
	var v []byte
	for _, a := range as {
		v = appendAlg(v, a)
	}
	m.Add(AttrPasswordAlgorithms, v)
}

// AddPasswordAlgorithm adds PASSWORD-ALGORITHM (RFC 8489 14.12).
func (m *Message) AddPasswordAlgorithm(a PasswordAlgorithm) {
	m.Add(AttrPasswordAlgorithm, appendAlg(nil, a))
}

func parseAlgs(v []byte) ([]PasswordAlgorithm, error) {
	var out []PasswordAlgorithm
	for len(v) > 0 {
		if len(v) < 4 || len(out) >= MaxAttributes {
			return nil, ErrBadAttribute
		}
		n := int(binary.BigEndian.Uint16(v[2:]))
		padded := (n + 3) &^ 3
		if padded > len(v)-4 {
			return nil, ErrBadAttribute
		}
		out = append(out, PasswordAlgorithm{Algorithm: binary.BigEndian.Uint16(v), Params: v[4 : 4+n]})
		v = v[4+padded:]
	}
	return out, nil
}

// PasswordAlgorithms decodes PASSWORD-ALGORITHMS.
func (m *Message) PasswordAlgorithms() ([]PasswordAlgorithm, error) {
	v, ok := m.Get(AttrPasswordAlgorithms)
	if !ok {
		return nil, ErrNoAttribute
	}
	return parseAlgs(v)
}

// PasswordAlgorithm decodes PASSWORD-ALGORITHM (exactly one entry).
func (m *Message) PasswordAlgorithm() (PasswordAlgorithm, error) {
	v, ok := m.Get(AttrPasswordAlgorithm)
	if !ok {
		return PasswordAlgorithm{}, ErrNoAttribute
	}
	as, err := parseAlgs(v)
	if err != nil || len(as) != 1 {
		return PasswordAlgorithm{}, ErrBadAttribute
	}
	return as[0], nil
}
