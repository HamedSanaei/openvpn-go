package client

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/failover"
	"github.com/hamedsanaei/openvpn-go/internal/observability"
)

// RetryPolicy controls each Connect or recovery sequence. A successful
// handshake starts a fresh budget for the next loss of connectivity.
type RetryPolicy struct {
	// MaxAttempts is the total attempt count per sequence. Zero tries each
	// endpoint once. UnlimitedAttempts keeps trying until canceled.
	// During automatic recovery, a full shared handshake queue consumes
	// one attempt and backs off without changing the selected endpoint.
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

type rejectedEndpointError struct{ failure *Error }

func (e rejectedEndpointError) Error() string { return e.failure.Error() }
func (e rejectedEndpointError) Unwrap() error { return e.failure }

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
	var rejected [MaxEndpoints]bool
	var cursors [MaxEndpoints]candidateCursor
	for {
		index := c.order[position]
		var delay time.Duration
		if (recovery || lost != "") && lost != CodeConfig {
			delay = backoff.Next(rand.N[time.Duration])
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
		started := time.Now()
		c.record(EventDialing, index, "", 0)
		c.mu.Unlock()

		progress := observability.Progress{Phase: observability.PhaseTransport, Started: started}
		link, stage, err, cleanupFailed := c.dial(observability.WithProgress(ctx, &progress), index, &cursors[index])
		c.mu.Lock()
		stopped := c.operationError(ctx, "connect")
		report := AttemptReport{Sequence: c.stats.Attempts, EndpointIndex: index, Stage: stage,
			Started: started, Duration: time.Since(started), RetryReason: lost, RetryAfter: delay}
		report.Phase, report.PhaseDuration = progress.Phase, time.Since(progress.Started)
		report.PhaseSteps = progress.Steps
		if err == nil && stopped == nil {
			c.stats.Connections++
			active := &connection{link: link, index: index, position: position, generation: c.stats.Connections, started: time.Now()}
			report.Stage, report.Generation = StageConnected, active.generation
			c.recordAttempt(report)
			c.active = active
			c.state = StateConnected
			if recovery {
				c.stats.Reconnects++
			}
			c.stats.ConnectedSince = active.started
			c.record(EventConnected, index, "", 0)
			c.mu.Unlock()
			return active, nil
		}
		if link != nil {
			c.mu.Unlock()
			cleanupFailed = failedCleanup(link.Close()) || cleanupFailed
			c.mu.Lock()
			stopped = c.operationError(ctx, "connect")
		}
		if cleanupFailed {
			c.cleanupFailed, report.CleanupFailed = true, true
		}
		if stopped == nil {
			lost = errorCode(err)
			report.Code = lost
			c.stats.AttemptFailures++
			c.stats.LastError = lost
			c.record(EventAttemptFailed, index, lost, 0)
		} else {
			report.Code = errorCode(stopped)
		}
		c.recordAttempt(report)
		c.mu.Unlock()
		if stopped != nil {
			err = stopped
		}
		if cleanupFailed {
			return nil, errors.Join(err, &Error{Op: "close unpublished attempt", Code: CodeCleanup})
		}
		if stopped != nil {
			return nil, err
		}
		if remaining > 0 {
			remaining--
		}
		capacity := recovery && lost == CodeCapacity && report.Phase == PhaseAdmission
		_, rejectedTarget := errors.AsType[rejectedEndpointError](err)
		if remaining == 0 || (!rejectedTarget && !capacity && !canRetry(lost)) {
			return nil, err
		}
		if rejectedTarget {
			rejected[position] = true
		}
		if _, same := errors.AsType[restartSameError](err); !same && !capacity {
			found := false
			for step := 1; step <= len(c.order); step++ {
				next := (position + step) % len(c.order)
				if !rejected[next] {
					position, found = next, true
					break
				}
			}
			if !found {
				return nil, err
			}
		}
	}
}

func canRetry(code ErrorCode) bool {
	return code == CodeNetwork || code == CodeTimeout || code == CodePeerRestart
}

func canRecover(code ErrorCode) bool {
	return code == CodeCapacity || canRetry(code)
}
