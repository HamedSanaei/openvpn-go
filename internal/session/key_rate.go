package session

import (
	"math"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/data"
)

type keyConsumptionRate struct {
	at                            time.Time
	usage                         data.KeyUsage
	sendRate, receiveRate         float64
	sendHeadroom, receiveHeadroom uint32
}

func (r *keyConsumptionRate) observe(now time.Time, usage data.KeyUsage, deadline time.Duration) {
	if !r.at.IsZero() && !now.After(r.at) {
		return
	}
	if !r.at.IsZero() && r.usage.Epoch == usage.Epoch {
		seconds := now.Sub(r.at).Seconds()
		r.sendRate = max(r.sendRate*0.875, float64(usage.Sent-r.usage.Sent)/seconds)
		r.receiveRate = max(r.receiveRate*0.875, float64(usage.Received-r.usage.Received)/seconds)
	}
	r.at, r.usage = now, usage
	// Leave room for detecting the rate on a scheduler tick and for
	// bursts while the bounded admission and TLS exchange are running.
	horizon := (deadline + 500*time.Millisecond).Seconds()
	limit := float64(usage.Limit / 4)
	r.sendHeadroom = uint32(min(limit, math.Ceil(r.sendRate*horizon)))
	r.receiveHeadroom = uint32(min(limit, math.Ceil(r.receiveRate*horizon)))
}

func (s *Session) sampleKeyRate(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rate.observe(now, s.channel.KeyUsage(), s.opts.HandshakeLimit)
	return s.rekeyDueLocked()
}

func (s *Session) rekeyDueLocked() bool {
	return s.channel.RekeyDueWithHeadroom(s.rate.sendHeadroom, s.rate.receiveHeadroom)
}
