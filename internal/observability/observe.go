package observability

import "sync/atomic"

const historySize = 64

// History stores the most recent events. The caller serializes access and
// can attach Sequence()+1 to each event before appending it.
type History[T any] struct {
	recent [historySize]T
	seq    uint64
}

func (h *History[T]) Sequence() uint64 { return h.seq }

func (h *History[T]) Append(event T) {
	h.recent[h.seq%historySize] = event
	h.seq++
}

func (h *History[T]) After(seq uint64) []T {
	if seq >= h.seq {
		return nil
	}
	seq = max(seq, h.seq-min(h.seq, historySize))
	events := make([]T, 0, h.seq-seq)
	for seq < h.seq {
		events = append(events, h.recent[seq%historySize])
		seq++
	}
	return events
}

// Traffic counts IP packets and plaintext bytes successfully forwarded.
type Traffic struct {
	packets, bytes atomic.Uint64
}

func (c *Traffic) Add(n int) {
	c.bytes.Add(uint64(n))
	c.packets.Add(1)
}

func (c *Traffic) Load() (packets, bytes uint64) {
	return c.packets.Load(), c.bytes.Load()
}

// QueueStats records drops and the observed high-water mark for a queue.
type QueueStats struct {
	Dropped   uint64
	HighWater uint64
}

type Queue struct {
	dropped   atomic.Uint64
	highWater atomic.Uint64
}

func (q *Queue) Drop(depth int) {
	q.dropped.Add(1)
	q.Observe(depth)
}

func (q *Queue) Observe(depth int) {
	candidate := uint64(depth)
	for old := q.highWater.Load(); candidate > old; old = q.highWater.Load() {
		if q.highWater.CompareAndSwap(old, candidate) {
			return
		}
	}
}

func (q *Queue) Stats() QueueStats {
	return QueueStats{Dropped: q.dropped.Load(), HighWater: q.highWater.Load()}
}
