package control

import "time"

const (
	controlReplaySize = 64
	controlReplayAge  = 15 * time.Second
)

// replayWindow tracks the authenticated outer counter independently of the
// reliable message ID. A newer counter starts the expiry of the holes it
// reveals. Later advancement leaves those holes' expiry times unchanged.
type replayWindow struct {
	timestamp uint32
	highest   uint32
	bits      uint64
	expires   [controlReplaySize]time.Time
}

func (w *replayWindow) admissible(counter, timestamp uint32, now time.Time) bool {
	switch {
	case counter == 0:
		return false
	case w.highest == 0 || timestamp > w.timestamp:
		return true
	case timestamp < w.timestamp:
		return false
	case counter > w.highest:
		return true
	default:
		distance := w.highest - counter
		return distance < controlReplaySize && w.bits&(uint64(1)<<distance) == 0 &&
			!now.After(w.expires[counter%controlReplaySize])
	}
}

func (w *replayWindow) accept(counter, timestamp uint32, now time.Time) bool {
	if !w.admissible(counter, timestamp, now) {
		return false
	}
	if timestamp > w.timestamp {
		*w = replayWindow{timestamp: timestamp}
	}
	if counter <= w.highest {
		w.bits |= uint64(1) << (w.highest - counter)
		return true
	}
	first := w.highest + 1
	if counter >= controlReplaySize {
		first = max(first, counter-controlReplaySize+1)
	}
	deadline := now.Add(controlReplayAge)
	for missing := first; missing < counter; missing++ {
		w.expires[missing%controlReplaySize] = deadline
	}
	w.bits = 1 | w.bits<<(counter-w.highest)
	w.highest = counter
	return true
}
