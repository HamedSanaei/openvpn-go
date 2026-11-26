package data

import "time"

const (
	replaySize = 64
	replayAge  = 15 * time.Second
)

// replay accepts increasing packet IDs on TCP. For UDP it also accepts holes
// within the last 64 IDs for 15 seconds from the first newer packet.
type replay struct {
	high uint32
	seen uint64
	gaps [replaySize]time.Time
}

func (r *replay) admissible(id uint32, udp bool, now time.Time) bool {
	if id == 0 {
		return false
	}
	if id > r.high {
		return true
	}
	distance := r.high - id
	return udp && distance < replaySize && r.seen&(uint64(1)<<distance) == 0 &&
		!now.After(r.gaps[id%replaySize])
}

// commit is called only after successful AEAD authentication.
func (r *replay) commit(id uint32, udp bool, now time.Time) {
	if id <= r.high {
		r.seen |= uint64(1) << (r.high - id)
		return
	}
	if udp {
		start := r.high + 1
		if id >= replaySize {
			start = max(start, id-(replaySize-1))
		}
		for hole := start; hole < id; hole++ {
			r.gaps[hole%replaySize] = now.Add(replayAge)
		}
	}
	r.seen = 1 | r.seen<<(id-r.high)
	r.high = id
}
