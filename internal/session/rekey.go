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
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
)

type replacement struct {
	id     uint8
	stream *control.Stream
	link   *tlscontrol.Link
	keys   crypt.DataKeys
	err    error
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
		s.opts.TLS.Auth.Clear()
		s.mu.Lock()
		s.channel = nil
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
		active.Close()
		stream, err := s.mux.StartRekey(id, first)
		if err != nil {
			return rekeyError(err)
		}
		pending = stream
		previous := active.Info
		workers.Go(func() {
			ctx, cancel := context.WithTimeout(s.ctx, s.opts.HandshakeLimit)
			defer cancel()
			result := replacement{id: id, stream: stream}
			result.link, result.err = tlscontrol.Establish(ctx, stream, s.opts.TLS, &previous)
			if result.err == nil {
				result.keys, result.err = result.link.DataKeys()
			}
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
			if result.err != nil {
				s.terminal = rekeyError(result.err)
				return
			}
			s.mu.Lock()
			err := s.channel.Promote(result.id, result.keys, time.Now().Add(rekeyOverlap))
			if err == nil {
				s.info = result.link.Info
				s.keyID = result.id
			}
			s.mu.Unlock()
			if err != nil {
				s.terminal = rekeyError(err)
				return
			}

			s.mux.Expect(result.stream, data.NextKeyID(result.id))
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
			if pending == nil && !now.Before(nextRekey) {
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
