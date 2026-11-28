package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
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

func TestAutomaticRecoveryRetriesFullAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		queue  int
		budget int
		cause  error
		stop   bool
		want   ErrorCode
	}{
		{"zero_queue", 0, UnlimitedAttempts, net.ErrClosed, false, ""},
		{"full_queue", 1, UnlimitedAttempts, net.ErrClosed, false, ""},
		{"rekey", 0, UnlimitedAttempts, &Error{Op: "admit handshake", Code: CodeCapacity}, false, ""},
		{"finite_budget", 0, 2, net.ErrClosed, false, CodeCapacity},
		{"cancel", 0, UnlimitedAttempts, net.ErrClosed, false, CodeCanceled},
		{"reconnect_disabled", 0, UnlimitedAttempts, net.ErrClosed, true, CodeNetwork},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				limiter, err := NewHandshakeLimiter(1, tc.queue)
				if err != nil {
					t.Fatal(err)
				}
				var dials []string
				c := retryClient(t, fallbackEndpoints, RetryPolicy{
					MaxAttempts: tc.budget, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond, DisableReconnect: tc.stop,
				}, testkit.DialerFunc(func(_ context.Context, _, address string) (transport.PacketConn, error) {
					dials = append(dials, address)
					raw, peer := testkit.PacketPipe(0, 64)
					t.Cleanup(func() { peer.Close() })
					return raw, nil
				}))
				c.config.HandshakeLimiter = limiter
				c.handshakes[0] = func(_ context.Context, _ Endpoint, raw transport.PacketConn) (tunnel.PacketConn, error) {
					if len(dials) == 1 {
						return &failedReader{PacketConn: raw, cause: tc.cause}, nil
					}
					return raw, nil
				}
				if err := c.Connect(t.Context()); err != nil {
					t.Fatal(err)
				}
				release, err := limiter.acquire(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { release() }()
				waitCtx, cancelWait := context.WithCancel(t.Context())
				defer cancelWait()
				waiter := make(chan error, 1)
				if tc.queue != 0 {
					go func() {
						_, err := limiter.acquire(waitCtx)
						waiter <- err
					}()
					synctest.Wait()
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				device, app := testkit.PacketPipe(1, 64)
				defer app.Close()
				result := make(chan error, 1)
				go func() { result <- c.Run(ctx, device) }()
				time.Sleep(4 * time.Millisecond)
				synctest.Wait()
				if len(dials) != 1 {
					t.Fatalf("dialed without admission: %v", dials)
				}
				stats := limiter.Stats()
				if tc.stop {
					assertCode(t, <-result, tc.want)
					if stats.Rejected != 0 {
						t.Fatalf("unexpected recovery while disabled: %+v", stats)
					}
					return
				}
				if stats.InFlight != 1 || stats.Waiting != tc.queue || stats.Rejected == 0 {
					t.Fatalf("recovery did not stay within admission: %+v", stats)
				}
				if tc.want != "" {
					if tc.want == CodeCanceled {
						cancel()
					}
					assertCode(t, <-result, tc.want)
					if tc.want == CodeCapacity && stats.Rejected != uint64(tc.budget) {
						t.Fatalf("admission attempts ignored the finite budget: %+v", stats)
					}
					return
				}
				select {
				case err := <-result:
					t.Fatalf("recovery exited during backpressure: %v", err)
				default:
				}
				if tc.queue != 0 {
					cancelWait()
					if err := <-waiter; !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
				}
				// Return the held permit once, then give the jitter timer time
				// to trigger the recovery attempt.
				release()
				release = func() {}
				time.Sleep(2 * time.Millisecond)
				synctest.Wait()
				expected := fallbackEndpoints[1].address()
				if errorCode(tc.cause) == CodeCapacity {
					expected = fallbackEndpoints[0].address()
				}
				if len(dials) != 2 || dials[1] != expected || c.Stats().Reconnects != 1 {
					t.Fatalf("recovery changed endpoint or failed: %v, %+v", dials, c.Stats())
				}
				cancel()
				assertCode(t, <-result, CodeCanceled)
				if stats := limiter.Stats(); stats.InFlight != 0 || stats.Waiting != 0 {
					t.Fatalf("unreleased admission: %+v", stats)
				}
			})
		})
	}
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
