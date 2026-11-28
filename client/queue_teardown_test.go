package client

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/observability"
	"github.com/hamedsanaei/openvpn-go/internal/session"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

type queueTeardownConn struct {
	transport.PacketConn
	entered chan struct{}
	resume  chan struct{}
	drops   atomic.Uint64
}

func (c *queueTeardownConn) Close() error {
	if c.entered != nil {
		close(c.entered)
		<-c.resume
	}
	return c.PacketConn.Close()
}

func (c *queueTeardownConn) QueueStats() (observability.QueueStats, observability.QueueStats) {
	count := c.drops.Load()
	return observability.QueueStats{Dropped: count, HighWater: count % 16},
		observability.QueueStats{Dropped: count + 6, HighWater: count%16 + 2}
}

func (*queueTeardownConn) RekeyResults() []session.RekeyResult {
	return []session.RekeyResult{{KeyID: 1}}
}

func TestQueueStatsRemainVisibleUntilTeardownFinishes(t *testing.T) {
	for _, explicitClose := range []bool{false, true} {
		name := "Run"
		if explicitClose {
			name = "Close"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			entered, resume := make(chan struct{}), make(chan struct{})
			var dials int
			var link *queueTeardownConn
			var peer transport.PacketConn
			c := retryClient(t, fallbackEndpoints[:1], RetryPolicy{DisableReconnect: true},
				testkit.DialerFunc(func(_ context.Context, _, _ string) (transport.PacketConn, error) {
					raw, remote := testkit.PacketPipe(1, 64)
					t.Cleanup(func() { remote.Close() })
					dials++
					next := &queueTeardownConn{PacketConn: raw}
					next.drops.Store(11)
					if dials == 1 {
						next.entered, next.resume = entered, resume
						next.drops.Store(17)
						link, peer = next, remote
					}
					return next, nil
				}))
			release := sync.OnceFunc(func() { close(resume) })
			defer release()
			if err := c.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			check := func(raw, inbound QueueStats, active int) bool {
				got := c.Stats()
				return got.CiphertextQueue == raw && got.InboundQueue == inbound && got.ActiveEndpointIndex == active
			}
			if !check(QueueStats{17, 1}, QueueStats{23, 3}, 0) {
				t.Fatalf("initial counters: %+v", c.Stats())
			}
			result := make(chan error, 1)
			if explicitClose {
				go func() { result <- c.Close() }()
			} else {
				device, app := testkit.PacketPipe(1, 64)
				defer device.Close()
				defer app.Close()
				go func() { result <- c.Run(ctx, device) }()
				peer.Close()
			}
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("session did not reach its cleanup barrier")
			}
			link.drops.Store(21)
			var readers sync.WaitGroup
			for range 8 {
				readers.Go(func() {
					for range 32 {
						if !check(QueueStats{21, 5}, QueueStats{27, 7}, -1) || len(c.RekeyReports()) != 1 {
							t.Error("closing counters or rekey history disappeared")
							return
						}
					}
				})
			}
			readers.Wait()
			release()
			select {
			case err := <-result:
				if explicitClose && err != nil {
					t.Fatal(err)
				}
				if !explicitClose {
					assertCode(t, err, CodeNetwork)
				}
			case <-ctx.Done():
				t.Fatal("session cleanup did not finish")
			}
			if !check(QueueStats{21, 5}, QueueStats{27, 7}, -1) || len(c.RekeyReports()) != 1 {
				t.Fatalf("final counters were lost or counted twice: %+v", c.Stats())
			}
			if !explicitClose {
				if err := c.Connect(ctx); err != nil {
					t.Fatal(err)
				}
				if !check(QueueStats{32, 11}, QueueStats{44, 13}, 0) {
					t.Fatalf("second generation was not aggregated once: %+v", c.Stats())
				}
			}
		})
	}
}
