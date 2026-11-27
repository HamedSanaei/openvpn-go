package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/observability"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
)

const rekeyHistorySize = 8

// RekeyResult is an internal snapshot of one soft reset attempt.
type RekeyResult struct {
	KeyID         uint8
	PeerInitiated bool
	Started       time.Time
	Duration      time.Duration
	Phase         observability.Phase
	Err           error
}

type replacement struct {
	stream *control.Stream
	link   *tlscontrol.Link
	keys   crypt.DataKeys
	report RekeyResult
}

type rekeyHistory struct {
	entries [rekeyHistorySize]RekeyResult
	count   uint64
}

func (s *Session) RekeyResults() []RekeyResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rekeys == nil {
		return nil
	}
	retained := min(s.rekeys.count, rekeyHistorySize)
	out := make([]RekeyResult, 0, retained)
	for i := s.rekeys.count - retained; i < s.rekeys.count; i++ {
		out = append(out, s.rekeys.entries[i%rekeyHistorySize])
	}
	return out
}

func (s *Session) recordRekey(report RekeyResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordRekeyLocked(report)
}

// Record installation under the same lock as the new key ID so readers
// cannot observe a promoted generation without its completed report.
func (s *Session) recordRekeyLocked(report RekeyResult) {
	report.Duration = time.Since(report.Started)
	if s.rekeys == nil {
		s.rekeys = new(rekeyHistory)
	}
	s.rekeys.entries[s.rekeys.count%rekeyHistorySize] = report
	s.rekeys.count++
}

type controlEnd struct {
	link *tlscontrol.Link
	err  error
}

func (s *Session) run(active *tlscontrol.Link) {
	var pending *control.Stream
	var workers sync.WaitGroup
	rekeyResults := make(chan replacement, 1)
	controlEnds := make(chan controlEnd, 2)
	watch := func(link *tlscontrol.Link) {
		workers.Go(func() {
			err := link.ReadUntilClosed()
			select {
			case controlEnds <- controlEnd{link: link, err: err}:
			case <-s.ctx.Done():
			}
		})
	}

	defer close(s.done)
	defer func() {
		s.cancel()
		if pending != nil {
			pending.Close()
		}
		active.Close()
		s.mux.Close()
		s.closeErr = s.raw.Close()
		workers.Wait()
		select {
		case result := <-rekeyResults:
			if result.report.Err == nil {
				result.report.Err = s.ctx.Err()
			}
			s.recordRekey(result.report)
		default:
		}
		s.opts.TLS.Auth.Clear()
		s.mu.Lock()
		if s.fragments != nil {
			s.fragments.clear()
		}
		s.channel = nil
		s.link = nil
		s.mu.Unlock()
		for len(s.inbound) > 0 {
			select {
			case packet := <-s.inbound:
				clear(packet)
			default:
			}
		}
	}()

	watch(active)
	nextRekey := time.Now().Add(s.opts.RekeyInterval)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()

	start := func(first control.Reset) error {
		if pending != nil {
			s.mux.RelayReset(first)
			return nil
		}
		s.mu.Lock()
		id := data.NextKeyID(s.channel.KeyID())
		s.mu.Unlock()
		if first.KeyID != 0 && first.KeyID != id {
			return nil
		}
		// OpenVPN processes control ACKs only on the primary key ID once a
		// soft reset begins. The previous data key is still usable.
		s.mu.Lock()
		s.link = nil
		s.mu.Unlock()
		active.Close()
		report := RekeyResult{KeyID: id, PeerInitiated: first.KeyID != 0, Started: time.Now(), Phase: observability.PhaseResetACK}
		stream, err := s.mux.StartRekey(id, first)
		if err != nil {
			report.Err = err
			s.recordRekey(report)
			return rekeyError(err)
		}
		pending = stream
		previous := active.Info
		workers.Go(func() {
			ctx, cancel := context.WithTimeout(s.ctx, s.opts.HandshakeLimit)
			defer cancel()
			progress := new(observability.Progress)
			ctx = observability.WithProgress(ctx, progress)
			result := replacement{stream: stream, report: report}
			result.link, result.report.Err = tlscontrol.Establish(ctx, stream, s.opts.TLS, &previous)
			if result.report.Err == nil {
				observability.Enter(ctx, observability.PhaseKeyDerivation)
				result.keys, result.report.Err = result.link.DataKeys()
			}
			result.report.Phase = progress.Phase
			rekeyResults <- result
		})
		return nil
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		case packet := <-s.mux.Data():
			s.receive(packet)
		case reset := <-s.mux.Resets():
			if err := start(reset); err != nil {
				s.terminal = err
				return
			}
		case <-s.rotate:
			if err := start(control.Reset{}); err != nil {
				s.terminal = err
				return
			}
		case result := <-rekeyResults:
			if result.report.Err != nil {
				s.recordRekey(result.report)
				s.terminal = rekeyError(result.report.Err)
				return
			}
			s.mu.Lock()
			err := s.channel.Promote(result.report.KeyID, result.keys, time.Now().Add(rekeyOverlap))
			if err == nil {
				if s.fragments != nil {
					s.fragments.retire(s.channel)
				}
				s.info = result.link.Info
				s.link = result.link
				s.keyID = result.report.KeyID
			}
			result.report.Err = err
			result.report.Phase = observability.PhaseRekeyInstall
			s.recordRekeyLocked(result.report)
			s.mu.Unlock()
			if err != nil {
				s.terminal = rekeyError(err)
				return
			}

			s.mux.Expect(result.stream, data.NextKeyID(result.report.KeyID))
			active, pending = result.link, nil
			watch(active)
			nextRekey = time.Now().Add(s.opts.RekeyInterval)
		case end := <-controlEnds:
			if end.link == active && (pending == nil || peerEndedSession(end.err)) {
				s.terminal = end.err
				return
			}
		case now := <-tick.C:
			if err := s.maintain(now); err != nil {
				s.terminal = err
				return
			}
			if s.opts.RekeyInterval > 0 && pending == nil && !now.Before(nextRekey) {
				if err := start(control.Reset{}); err != nil {
					s.terminal = err
					return
				}
			}
		}
	}
}

func peerEndedSession(err error) bool {
	return errors.Is(err, tlscontrol.ErrAuth) || errors.Is(err, tlscontrol.ErrPeerStopped) ||
		errors.Is(err, tlscontrol.ErrPeerRestart) || errors.Is(err, tlscontrol.ErrPeerRestartSame) ||
		errors.Is(err, tlscontrol.ErrNegotiation)
}

func (s *Session) maintain(now time.Time) error {
	s.mu.Lock()
	s.channel.Retire(now)
	if s.fragments != nil {
		s.fragments.expire(now)
		s.fragments.retire(s.channel)
	}
	idle := now.Sub(s.lastRecv)
	silent := now.Sub(s.lastSent)
	info := s.info
	s.mu.Unlock()
	if info.PingTimeout > 0 && idle >= info.PingTimeout {
		if info.PingExit {
			return tlscontrol.ErrPeerStopped
		}
		return context.DeadlineExceeded
	}
	if info.PingInterval > 0 && silent >= info.PingInterval {
		err := s.write(s.ctx, []byte(data.Keepalive))
		if errors.Is(err, net.ErrClosed) && s.ctx.Err() != nil {
			return nil
		}
		return err
	}
	return nil
}

func rekeyError(err error) error {
	return fmt.Errorf("%w: %w", ErrRekey, err)
}
