package session

import (
	"errors"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/data"
)

// MaxEarlyRekeyBytes bounds the extra ciphertext retained per session.
const MaxEarlyRekeyBytes = 64 << 10

const (
	maxEarlyRekeyFrames = 16
	maxEarlyRekeyAge    = time.Second
)

type earlyFrame struct {
	packet   []byte
	deadline time.Time
}

// earlyData belongs to the one outstanding control lane. Frames still pass
// through the normal authenticated receive and replay checks on installation.
type earlyData struct {
	frames []earlyFrame
	bytes  int
}

func (q *earlyData) expire(now time.Time) uint64 {
	n := 0
	for n < len(q.frames) && !now.Before(q.frames[n].deadline) {
		q.bytes -= len(q.frames[n].packet)
		clear(q.frames[n].packet)
		n++
	}
	if n != 0 {
		remaining := copy(q.frames, q.frames[n:])
		clear(q.frames[remaining:])
		q.frames = q.frames[:remaining]
	}
	return uint64(n)
}

func (q *earlyData) discard() uint64 {
	for _, frame := range q.frames {
		clear(frame.packet)
	}
	count := uint64(len(q.frames))
	*q = earlyData{}
	return count
}

func (s *Session) receiveDuringRekey(packet []byte, pending uint8, q *earlyData) {
	if err := s.receive(packet); !errors.Is(err, data.ErrKeyID) || pending == 0 || packet[0]&7 != pending {
		return
	}
	now := time.Now()
	s.earlyDrops.Add(q.expire(now))
	if len(q.frames) >= maxEarlyRekeyFrames || len(packet) > MaxEarlyRekeyBytes-q.bytes {
		clear(packet)
		s.earlyDrops.Add(1)
		return
	}
	q.frames = append(q.frames, earlyFrame{packet, now.Add(maxEarlyRekeyAge)})
	q.bytes += len(packet)
}

func (s *Session) finishEarlyData(q *earlyData, now time.Time) {
	s.earlyDrops.Add(q.expire(now))
	for _, frame := range q.frames {
		if err := s.receive(frame.packet); err != nil {
			clear(frame.packet)
			s.earlyDrops.Add(1)
		}
	}
	*q = earlyData{}
}
