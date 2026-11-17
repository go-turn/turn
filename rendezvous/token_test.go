package rendezvous

import (
	"strings"
	"testing"

	turnv1 "github.com/go-turn/turn/proto/turn/v1"
	"google.golang.org/grpc/codes"
)

func TestOverlongTokenRefused(t *testing.T) {
	f := newFix(t, nil)
	if _, err := f.c.CreateRoom(tctx(t, "user:"+strings.Repeat("a", 9<<10)), &turnv1.CreateRoomRequest{}); code(err) != codes.Unauthenticated {
		t.Fatalf("a 9 KiB token: %v", err)
	}
	// control: a long but bounded token reaches the verifier
	if _, err := f.c.CreateRoom(tctx(t, "user:"+strings.Repeat("a", 4<<10)), &turnv1.CreateRoomRequest{}); err != nil {
		t.Fatalf("a 4 KiB token: %v", err)
	}
}
