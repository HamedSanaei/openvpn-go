package control

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"

	"github.com/hamedsanaei/openvpn-go/internal/wire"
	"github.com/hamedsanaei/openvpn-go/transport"
)

var (
	ErrTransport  = errors.New("OpenVPN control transport failed")
	ErrReliable   = errors.New("OpenVPN reliable control channel failed")
	ErrRetransmit = errors.New("OpenVPN control retransmission budget exhausted")
)

// Stream runs the reliable control channel and presents TLS with a byte
// stream. The caller owns the packet transport and must close the stream
// before releasing the transport.
type Stream struct {
	conn    net.Conn
	cancel  context.CancelFunc
	ready   chan struct{}
	stopped chan struct{}
	done    chan struct{}
	drain   chan chan struct{}
	err     error
	local   wire.SessionID
	peer    wire.SessionID
}

func startStream(d *driver, limit, chunkSize int) *Stream {
	ctx, cancel := context.WithCancel(context.Background())
	conn, bridge := net.Pipe()
	s := &Stream{
		conn: conn, cancel: cancel, ready: make(chan struct{}), stopped: make(chan struct{}),
		done: make(chan struct{}), drain: make(chan chan struct{}), local: d.local,
	}
	go s.run(ctx, bridge, d, limit, chunkSize)
	return s
}

func (s *Stream) Conn() net.Conn { return s.conn }

// KeyContext is read after WaitReady succeeds and TLS authenticates the
// peer. The control session IDs become immutable when ready is closed.
func (s *Stream) KeyContext() (wire.SessionID, wire.SessionID) {
	return s.local, s.peer
}

// Err returns the driver cause once it has stopped, including before the
// bridge reports EOF to TLS.
func (s *Stream) Err() error {
	select {
	case <-s.stopped:
		return s.err
	default:
		return nil
	}
}

func (s *Stream) WaitReady(ctx context.Context) error {
	select {
	case <-s.ready:
		return nil
	case <-s.done:
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Drain flushes ACKs and waits until the peer has acknowledged our TLS
// messages. During rekey this completes the control flight before data uses
// the newly derived material.
func (s *Stream) Drain(ctx context.Context) error {
	flushed := make(chan struct{})
	select {
	case s.drain <- flushed:
	case <-s.done:
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-flushed:
		return nil
	case <-s.done:
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Stream) Close() {
	s.cancel()
	<-s.done
}

func (s *Stream) run(ctx context.Context, bridge net.Conn, d *driver, limit, chunkSize int) {
	incoming := make(chan []byte)
	outgoing := make(chan []byte)
	delivery := make(chan []byte)

	// A worker failure cancels a pending transport write as well as the driver.
	failures := make(chan error, 3)
	fail := func(err error) {
		failures <- err
		s.cancel()
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		buf := make([]byte, limit)
		for ctx.Err() == nil {
			n, err := d.packets.ReadPacket(ctx, buf)
			if err != nil {
				if d.udp && (errors.Is(err, transport.ErrEmptyPacket) || errors.Is(err, transport.ErrPacketTooLarge)) {
					continue
				}
				fail(ErrTransport)
				return
			}
			if n < 1 || n > len(buf) {
				fail(ErrTransport)
				return
			}
			if !post(ctx, incoming, buf[:n]) {
				return
			}
		}
	})
	workers.Go(func() {
		buf := make([]byte, chunkSize)
		for ctx.Err() == nil {
			n, err := bridge.Read(buf)
			if err != nil {
				fail(ErrTransport)
				return
			}
			if !post(ctx, outgoing, buf[:n]) {
				return
			}
		}
	})
	workers.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case payload := <-delivery:
				if _, err := bridge.Write(payload); err != nil {
					fail(ErrTransport)
					return
				}
			}
		}
	})

	s.err = d.loop(ctx, incoming, outgoing, delivery, s.drain, func() {
		s.peer = d.peer
		close(s.ready)
	})
	if errors.Is(s.err, context.Canceled) {
		select {
		case err := <-failures:
			s.err = err
		default:
		}
	}
	close(s.stopped)
	s.cancel()
	bridge.Close()
	workers.Wait()
	d.packets.Close()
	close(s.done)
}

func post(ctx context.Context, to chan<- []byte, payload []byte) bool {
	owned := bytes.Clone(payload)
	select {
	case to <- owned:
		return true
	case <-ctx.Done():
		return false
	}
}
