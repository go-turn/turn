package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestKeepRenewedAheadOfExpiryRetriesUnavailableStopsOnUnauthenticated(t *testing.T) {
	old := retryUnavailable
	retryUnavailable = 20 * time.Millisecond
	t.Cleanup(func() { retryUnavailable = old })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	var calls, updates []string
	var firstAt time.Duration
	err := KeepRenewed(ctx, Session{Token: "t0", Expires: start.Add(400 * time.Millisecond)}, 100*time.Millisecond,
		func(_ context.Context, tok string) (Session, error) {
			calls = append(calls, tok)
			switch len(calls) {
			case 1:
				firstAt = time.Since(start)
				return Session{}, status.Error(codes.Unavailable, "provider down") // same token, retried
			case 2:
				return Session{Token: "t1", Expires: time.Now().Add(100 * time.Millisecond)}, nil
			}
			return Session{}, status.Error(codes.Unauthenticated, "unauthorized")
		},
		func(s Session) { updates = append(updates, s.Token) })
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("ended with %v", err)
	}
	if len(calls) != 3 || calls[0] != "t0" || calls[1] != "t0" || calls[2] != "t1" || len(updates) != 1 || updates[0] != "t1" {
		t.Fatalf("calls %v updates %v", calls, updates)
	}
	// 400 ms expiry minus the 100 ms lead: not at once, not after the expiry.
	if firstAt < 250*time.Millisecond || firstAt > 400*time.Millisecond {
		t.Fatalf("first renewal at %v, want about 300 ms", firstAt)
	}
}

func TestKeepRenewedStopsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- KeepRenewed(ctx, Session{Token: "t", Expires: time.Now().Add(time.Hour)}, time.Minute,
			func(context.Context, string) (Session, error) { t.Error("renewed too early"); return Session{}, nil }, func(Session) {})
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("KeepRenewed ignored its context")
	}
}
