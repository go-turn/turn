package client

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// MaxFrameBytes bounds one SSE line the client will read.
const MaxFrameBytes = 1 << 20

// Frame is one dispatched Server-Sent Event (WHATWG HTML §9.2.6).
type Frame struct {
	Event string // "message" when the stream names none
	Data  string // data lines joined with "\n"
	ID    string
}

// ParseSSE reads an event stream and calls fn for each event. Comment lines
// (": ...") and unknown fields are ignored; a stream that ends mid-event drops
// that event, as the specification says. It returns fn's error, a read error,
// or nil at a clean end.
func ParseSSE(r io.Reader, fn func(Frame) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), MaxFrameBytes)
	var f Frame
	var data []string
	has := false
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if has {
				f.Data = strings.Join(data, "\n")
				if f.Event == "" {
					f.Event = "message"
				}
				if err := fn(f); err != nil {
					return err
				}
			}
			f, data, has = Frame{}, nil, false
			continue
		}
		if line[0] == ':' {
			continue
		}
		name, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch name {
		case "event":
			f.Event, has = value, true
		case "data":
			data, has = append(data, value), true
		case "id":
			if !strings.Contains(value, "\x00") {
				f.ID = value
			}
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return errors.New("rendezvous: event stream line too long")
		}
		return err
	}
	return nil
}
