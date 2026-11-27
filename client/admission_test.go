package client

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

func TestHandshakeLimiterFIFOAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limiter, err := NewHandshakeLimiter(1, 3)
		if err != nil {
			t.Fatal(err)
		}
		initial, err := limiter.acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		type result struct {
			id      int
			err     error
			release func()
		}
		out := make(chan result, 3)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		for id, candidate := range []context.Context{t.Context(), ctx, t.Context()} {
			go func() {
				release, err := limiter.acquire(candidate)
				out <- result{id, err, release}
			}()
			synctest.Wait()
		}
		if _, err := limiter.acquire(t.Context()); errorCode(err) != CodeCapacity {
			t.Fatalf("queue overflow: %v", err)
		}
		cancel()
		if r := <-out; r.id != 1 || !errors.Is(r.err, context.Canceled) {
			t.Fatalf("waiting cancellation: %+v", r)
		}
		initial()
		for _, id := range []int{0, 2} {
			r := <-out
			if r.id != id || r.err != nil {
				t.Fatalf("admission order: %+v", r)
			}
			r.release()
		}
		if got := limiter.Stats(); got != (HandshakeStats{PeakInFlight: 1, PeakWaiting: 3, Rejected: 1}) {
			t.Fatalf("unexpected admission totals: %+v", got)
		}
	})
}

func TestSharedAdmissionBoundsClientDialEntries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limiter, err := NewHandshakeLimiter(2, 3)
		if err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{}, 5)
		clients := make([]*Client, 6)
		for i := range clients {
			c := createTestClient(t, testkit.DialerFunc(func(ctx context.Context, _, _ string) (transport.PacketConn, error) {
				entered <- struct{}{}
				<-ctx.Done()
				return nil, ctx.Err()
			}))
			c.config.HandshakeLimiter = limiter
			clients[i] = c
			defer c.Close()
		}
		results := make(chan error, 5)
		for _, c := range clients[:5] {
			go func() { results <- c.Connect(t.Context()) }()
			synctest.Wait()
		}
		if len(entered) != 2 || limiter.Stats().Waiting != 3 {
			t.Fatal("shared admission did not cap concurrent dials")
		}
		assertCode(t, clients[5].Connect(t.Context()), CodeCapacity)
		if reports := clients[5].AttemptReports(0); len(reports) != 1 || reports[0].Phase != PhaseAdmission {
			t.Fatalf("admission phase was not reported: %+v", reports)
		}
		if err := clients[0].Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if len(entered) != 3 || limiter.Stats().InFlight != 2 {
			t.Fatal("a queued client was not admitted after cancellation")
		}
		for _, c := range clients[1:5] {
			c.Close()
		}
		for range clients[:5] {
			assertCode(t, <-results, CodeClosed)
		}
		if stats := limiter.Stats(); stats.InFlight != 0 || stats.Waiting != 0 || stats.PeakInFlight != 2 {
			t.Fatalf("leaked admission: %+v", stats)
		}
	})
}
