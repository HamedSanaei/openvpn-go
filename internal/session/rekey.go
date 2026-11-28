package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
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
	KeyUsage      bool
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

type rekeyAdmission struct {
	ctx  context.Context
	done func()
	err  error
}

func (s *Session) run(active *tlscontrol.Link) {
	var pending *control.Stream
	var waiting *RekeyResult
	var queuedReset control.Reset
	var workers sync.WaitGroup
	rekeyResults := make(chan replacement, 1)
	controlEnds := make(chan controlEnd, 2)
	admissions := make(chan rekeyAdmission)
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
		if waiting != nil {
			waiting.PeerInitiated = queuedReset.KeyID != 0
			waiting.Err, waiting.Phase = s.ctx.Err(), observability.PhaseAdmission
			s.recordRekey(*waiting)
		}
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
	s.sampleKeyRate(time.Now())
	nextRekey := time.Now().Add(s.opts.RekeyInterval)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()

	open := func(first control.Reset, report RekeyResult, admission rekeyAdmission) error {
		report.PeerInitiated = first.KeyID != 0
		report.KeyUsage = report.KeyUsage && !report.PeerInitiated
		if admission.err == nil {
			admission.err = admission.ctx.Err()
		}
		if admission.err != nil {
			admission.done()
			report.Err, report.Phase = admission.err, observability.PhaseAdmission
			s.recordRekey(report)
			return rekeyError(admission.err)
		}
		// A UDP peer may still be retransmitting its previous key exchange
		// when we start locally. Keep that stream available to ACK the
		// retransmission until the peer responds on the next key ID.
		keepPrevious := first.KeyID == 0 && strings.HasPrefix(s.opts.TLS.Network, "udp")
		s.mu.Lock()
		s.link = nil
		s.mu.Unlock()
		previous := active
		if !keepPrevious {
			previous.Close()
		}
		stream, err := s.mux.StartRekey(report.KeyID, first)
		if err != nil {
			admission.done()
			report.Err = err
			s.recordRekey(report)
			return rekeyError(err)
		}
		pending = stream
		workers.Go(func() {
			defer admission.done()
			progress := new(observability.Progress)
			ctx := observability.WithProgress(admission.ctx, progress)
			result := replacement{stream: stream, report: report}
			if keepPrevious {
				observability.Enter(ctx, observability.PhaseResetACK)
				if err := stream.WaitReady(ctx); err != nil {
					result.report.Err, result.report.Phase = err, progress.Phase
					rekeyResults <- result
					return
				}
				previous.Close()
			}
			result.link, result.report.Err = tlscontrol.Establish(ctx, stream, s.opts.TLS, &previous.Info)
			if result.report.Err == nil {
				observability.Enter(ctx, observability.PhaseKeyDerivation)
				result.keys, result.report.Err = result.link.DataKeys()
			}
			result.report.Phase = progress.Phase
			rekeyResults <- result
		})
		return nil
	}

	start := func(first control.Reset, keyUsage bool) error {
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
		if waiting != nil {
			// A peer reset can arrive during local admission. Preserve
			// the first authenticated reset, including on TCP.
			if queuedReset.KeyID == 0 && first.KeyID != 0 {
				queuedReset = first
			}
			return nil
		}
		report := RekeyResult{KeyID: id, KeyUsage: keyUsage, Started: time.Now(), Phase: observability.PhaseResetACK}
		ctx, cancel := context.WithTimeout(s.ctx, s.opts.HandshakeLimit)
		if s.opts.AcquireHandshake == nil {
			return open(first, report, rekeyAdmission{ctx: ctx, done: cancel})
		}
		waiting, queuedReset = &report, first
		workers.Go(func() {
			release, err := s.opts.AcquireHandshake(ctx)
			admission := rekeyAdmission{ctx: ctx, err: err, done: func() {
				cancel()
				if release != nil {
					release()
				}
			}}
			select {
			case admissions <- admission:
			case <-s.ctx.Done():
				admission.done()
			}
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
			if err := start(reset, false); err != nil {
				s.terminal = err
				return
			}
		case <-s.rotate:
			if !s.currentKeyNeedsRekey() {
				continue
			}
			if err := start(control.Reset{}, true); err != nil {
				s.terminal = err
				return
			}
		case admission := <-admissions:
			report, first := *waiting, queuedReset
			waiting, queuedReset = nil, control.Reset{}
			if first.KeyID == 0 {
				select {
				case reset := <-s.mux.Resets():
					if reset.KeyID == report.KeyID {
						first = reset
					}
				default:
				}
			}
			if err := open(first, report, admission); err != nil {
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
			if s.sampleKeyRate(now) {
				s.requestRekey()
			}
			if err := s.maintain(now); err != nil {
				s.terminal = err
				return
			}
			if s.opts.RekeyInterval > 0 && pending == nil && waiting == nil && !now.Before(nextRekey) {
				if err := start(control.Reset{}, false); err != nil {
					s.terminal = err
					return
				}
			}
		}
	}
}

func (s *Session) currentKeyNeedsRekey() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rekeyDueLocked()
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
