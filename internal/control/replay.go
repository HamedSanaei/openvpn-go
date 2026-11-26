package control

import "time"

// replayWindow tracks the authenticated outer counter separately from reliable
// message IDs. Unseen out-of-order IDs within the window remain admissible.
type replayWindow struct {
	initialized bool
	timestamp   uint32
	highest     uint32
	bits        uint64
	advancedAt  time.Time
}

func (w *replayWindow) accept(counter, timestamp uint32, now time.Time) bool {
	switch {
	case counter == 0:
		return false
	case !w.initialized || timestamp > w.timestamp:
		*w = replayWindow{true, timestamp, counter, 1, now}
		return true
	case timestamp < w.timestamp:
		return false
	case counter > w.highest:
		w.bits = 1 | w.bits<<(counter-w.highest)
		w.highest = counter
		w.advancedAt = now
		return true
	default:
		distance := w.highest - counter
		if distance >= 64 || w.bits&(uint64(1)<<distance) != 0 || now.Sub(w.advancedAt) > 15*time.Second {
			return false
		}
		w.bits |= uint64(1) << distance
		return true
	}
}
