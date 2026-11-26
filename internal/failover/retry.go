package failover

import (
	"context"
	"time"
)

// Order returns the indexes of the declared candidates in attempt order.
func Order(count int, shuffle func(int, func(int, int))) []int {
	order := make([]int, count)
	for i := range order {
		order[i] = i
	}
	if shuffle != nil {
		shuffle(count, func(i, j int) { order[i], order[j] = order[j], order[i] })
	}
	return order
}

// Backoff doubles the delay ceiling up to the configured maximum.
type Backoff struct {
	next, maximum time.Duration
}

func NewBackoff(initial, maximum time.Duration) Backoff {
	return Backoff{next: initial, maximum: maximum}
}

// Next applies equal jitter, uniformly sampling between half the current
// ceiling and the full ceiling. random returns a value in [0, n).
func (b *Backoff) Next(random func(time.Duration) time.Duration) time.Duration {
	ceiling := b.next
	if b.next >= b.maximum-b.next {
		b.next = b.maximum
	} else {
		b.next *= 2
	}
	floor := ceiling / 2
	return floor + random(ceiling-floor+1)
}

// Wait holds an attempt until its backoff elapses or the operation is canceled.
func Wait(ctx context.Context, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
