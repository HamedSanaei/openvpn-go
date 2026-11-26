package client

import (
	"context"
	"math/rand/v2"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/failover"
)

// RetryPolicy controls each Connect or recovery sequence. A successful
// handshake starts a fresh budget for the next loss of connectivity.
type RetryPolicy struct {
	// MaxAttempts is the total attempt count per sequence. Zero tries each
	// endpoint once. UnlimitedAttempts keeps trying until canceled.
	MaxAttempts int
	// InitialBackoff and MaxBackoff set the delay ceilings. Zero selects
	// 250 milliseconds and 10 seconds, respectively. Jitter samples between
	// half the ceiling and the ceiling. The maximum is at least the initial
	// ceiling when only InitialBackoff is set.
	InitialBackoff, MaxBackoff time.Duration
	// DisableReconnect returns from Run after a lost session.
	DisableReconnect bool
}

// UnlimitedAttempts opts in to a cancellable retry sequence without an
// attempt-count limit.
const UnlimitedAttempts = -1

func (p *RetryPolicy) normalize(endpoints int) bool {
	if p.MaxAttempts == 0 {
		p.MaxAttempts = endpoints
	}
	if p.InitialBackoff == 0 {
		p.InitialBackoff = 250 * time.Millisecond
	}
	if p.MaxBackoff == 0 {
		p.MaxBackoff = max(10*time.Second, p.InitialBackoff)
	}
	return p.MaxAttempts >= UnlimitedAttempts && p.MaxAttempts <= 1024 &&
		p.InitialBackoff >= time.Millisecond && p.MaxBackoff >= p.InitialBackoff && p.MaxBackoff <= 5*time.Minute
}

// establish is called exclusively by the owner of Connect or Run. It starts
// at a position in the fixed order and wraps around within the attempt budget.
func (c *Client) establish(ctx context.Context, start int, recovery bool, lost ErrorCode) (*connection, error) {
	policy := c.config.Retry
	backoff := failover.NewBackoff(policy.InitialBackoff, policy.MaxBackoff)
	position := start
	remaining := policy.MaxAttempts
	for {
		index := c.order[position]
		if recovery || lost != "" {
			delay := backoff.Next(rand.N[time.Duration])
			c.mu.Lock()
			if err := c.operationError(ctx, "connect"); err != nil {
				c.mu.Unlock()
				return nil, err
			}
			c.state = StateBackoff
			c.record(EventRetryScheduled, index, lost, delay)
			c.mu.Unlock()
			failover.Wait(ctx, delay)
		}

		c.mu.Lock()
		if err := c.operationError(ctx, "connect"); err != nil {
			c.mu.Unlock()
			return nil, err
		}
		c.state = StateDialing
		c.stats.Attempts++
		c.record(EventDialing, index, "", 0)
		c.mu.Unlock()

		link, err := c.dial(ctx, index)
		c.mu.Lock()
		stopped := c.operationError(ctx, "connect")
		if err == nil && stopped == nil {
			active := &connection{link: link, index: index, position: position}
			c.active = active
			c.state = StateConnected
			c.stats.Connections++
			if recovery {
				c.stats.Reconnects++
			}
			c.stats.ConnectedSince = time.Now()
			c.record(EventConnected, index, "", 0)
			c.mu.Unlock()
			return active, nil
		}
		if stopped == nil {
			lost = errorCode(err)
			c.stats.AttemptFailures++
			c.stats.LastError = lost
			c.record(EventAttemptFailed, index, lost, 0)
		}
		c.mu.Unlock()
		if link != nil {
			link.Close()
		}
		if stopped != nil {
			return nil, stopped
		}
		if remaining > 0 {
			remaining--
		}
		if remaining == 0 || !canRetry(lost) {
			return nil, err
		}
		position = (position + 1) % len(c.order)
	}
}

func canRetry(code ErrorCode) bool {
	return code == CodeNetwork || code == CodeTimeout || code == CodePeerRestart
}
