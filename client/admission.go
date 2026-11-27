package client

import (
	"container/list"
	"context"
	"sync"
)

// HandshakeLimiter bounds connection attempts and TLS rekeys across the
// clients that explicitly share it. Its waiting queue is FIFO and bounded.
type HandshakeLimiter struct {
	mu       sync.Mutex
	max      int
	maxQueue int
	queue    list.List
	stats    HandshakeStats
}

// HandshakeStats contains process-local admission counters.
type HandshakeStats struct {
	InFlight     int
	Waiting      int
	PeakInFlight int
	PeakWaiting  int
	Rejected     uint64
}

type handshakeWaiter struct {
	ready chan struct{}
	node  *list.Element
}

// NewHandshakeLimiter sets a positive attempt limit and a bounded queue.
// A zero queue rejects attempts whenever all slots are in use.
func NewHandshakeLimiter(inFlight, waiting int) (*HandshakeLimiter, error) {
	if inFlight < 1 || inFlight > 4096 || waiting < 0 || waiting > 4096 {
		return nil, configError("handshake admission limits")
	}
	return &HandshakeLimiter{max: inFlight, maxQueue: waiting}, nil
}

func (l *HandshakeLimiter) Stats() HandshakeStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stats
}

func (l *HandshakeLimiter) acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.stats.InFlight < l.max {
		l.stats.InFlight++
		l.stats.PeakInFlight = max(l.stats.PeakInFlight, l.stats.InFlight)
		l.mu.Unlock()
		return l.release, nil
	}
	if l.queue.Len() >= l.maxQueue {
		l.stats.Rejected++
		l.mu.Unlock()
		return nil, &Error{Op: "admit handshake", Code: CodeCapacity}
	}
	waiter := &handshakeWaiter{ready: make(chan struct{})}
	waiter.node = l.queue.PushBack(waiter)
	l.stats.Waiting++
	l.stats.PeakWaiting = max(l.stats.PeakWaiting, l.stats.Waiting)
	l.mu.Unlock()
	select {
	case <-waiter.ready:
		if err := ctx.Err(); err != nil {
			l.release()
			return nil, err
		}
		return l.release, nil
	case <-ctx.Done():
		l.mu.Lock()
		if waiter.node == nil {
			l.releaseLocked()
		} else {
			l.queue.Remove(waiter.node)
			l.stats.Waiting--
		}
		l.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (l *HandshakeLimiter) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.releaseLocked()
}

func (l *HandshakeLimiter) releaseLocked() {
	if first := l.queue.Front(); first != nil {
		waiter := l.queue.Remove(first).(*handshakeWaiter)
		waiter.node = nil
		l.stats.Waiting--
		close(waiter.ready)
		return
	}
	l.stats.InFlight--
}
