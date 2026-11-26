package testkit

import (
	"sync"
	"time"
)

// Clock is a manual clock whose timers advance only through Advance.
type Clock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[*Timer]struct{}
}

// NewClock starts a clock at the given time.
func NewClock(start time.Time) *Clock {
	return &Clock{now: start, timers: make(map[*Timer]struct{})}
}

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// NewTimer creates a one-shot timer. Nonpositive durations signal immediately.
func (c *Clock) NewTimer(d time.Duration) *Timer {
	c.mu.Lock()
	defer c.mu.Unlock()

	timer := &Timer{clock: c, deadline: c.now.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		timer.ch <- c.now
	} else {
		c.timers[timer] = struct{}{}
	}
	return timer
}

// Advance moves the clock forward and makes all due timers ready.
func (c *Clock) Advance(d time.Duration) {
	if d < 0 {
		panic("test clock cannot move backwards")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
	for timer := range c.timers {
		if !timer.deadline.After(c.now) {
			delete(c.timers, timer)
			timer.ch <- timer.deadline
		}
	}
}

// Timer belongs to a Clock and may be stopped before it fires.
type Timer struct {
	clock    *Clock
	deadline time.Time
	ch       chan time.Time
}

func (t *Timer) C() <-chan time.Time { return t.ch }

// Stop prevents a pending timer from signaling and reports whether it was
// pending. A timer that already fired retains its signal.
func (t *Timer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if _, pending := t.clock.timers[t]; !pending {
		return false
	}
	delete(t.clock.timers, t)
	return true
}
