package stun

import (
	"encoding/binary"
	"errors"
	"io"
)

// ChannelData framing, RFC 8656 section 12.4.
const (
	ChannelMin = 0x4000
	ChannelMax = 0x4FFF
	// MaxChannelData is the largest ChannelData payload.
	MaxChannelData = 65535
)

// Errors of the ChannelData codec.
var (
	ErrBadChannel = errors.New("stun: channel number out of 0x4000-0x4FFF")
	ErrBadFrame   = errors.New("stun: not a STUN message or ChannelData")
)

// ChannelData is one channel-framed datagram.
type ChannelData struct {
	Number uint16
	Data   []byte
}

// IsChannelData reports whether b starts like ChannelData (first byte 64-79).
func IsChannelData(b []byte) bool { return len(b) >= 4 && b[0]>>4 == 4 }

// DecodeChannelData parses exactly one ChannelData frame occupying b. Padding
// to a multiple of 4 is accepted (required on streams, optional on UDP); any
// other trailing byte is refused. Data aliases b.
func DecodeChannelData(b []byte) (ChannelData, error) {
	if len(b) < 4 {
		return ChannelData{}, ErrShort
	}
	ch := binary.BigEndian.Uint16(b)
	if ch < ChannelMin || ch > ChannelMax {
		return ChannelData{}, ErrBadChannel
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n > len(b)-4 {
		return ChannelData{}, ErrBadLength
	}
	if len(b) > 4+((n+3)&^3) {
		return ChannelData{}, ErrBadLength
	}
	return ChannelData{Number: ch, Data: b[4 : 4+n : 4+n]}, nil
}

// AppendTo encodes the frame, padded to 4 bytes when pad is set (streams).
func (c ChannelData) AppendTo(dst []byte, pad bool) []byte {
	dst = binary.BigEndian.AppendUint16(dst, c.Number)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(c.Data)))
	dst = append(dst, c.Data...)
	if pad {
		for i := len(c.Data); i%4 != 0; i++ {
			dst = append(dst, 0)
		}
	}
	return dst
}

// ReadFrame reads one STUN message or ChannelData frame (padded) from a
// stream. buf is reused and returned grown as needed; the frame aliases it
// and is valid until the next call. Memory is bounded by MaxMessageSize.
func ReadFrame(r io.Reader, buf []byte) (frame, newbuf []byte, err error) {
	if cap(buf) < HeaderSize {
		buf = make([]byte, 0, 2048)
	}
	buf = buf[:4]
	if _, err = io.ReadFull(r, buf); err != nil {
		return nil, buf, err
	}
	var total int
	switch {
	case buf[0]>>6 == 0:
		n := int(binary.BigEndian.Uint16(buf[2:]))
		if n%4 != 0 {
			return nil, buf, ErrUnaligned
		}
		total = HeaderSize + n
	case buf[0]>>4 == 4:
		total = 4 + ((int(binary.BigEndian.Uint16(buf[2:])) + 3) &^ 3)
	default:
		return nil, buf, ErrBadFrame
	}
	if cap(buf) < total {
		nb := make([]byte, total)
		copy(nb, buf[:4])
		buf = nb
	}
	buf = buf[:total]
	if _, err = io.ReadFull(r, buf[4:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, buf, err
	}
	return buf, buf, nil
}
