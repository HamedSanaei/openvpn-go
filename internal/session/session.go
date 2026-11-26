package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/transport"
)

const (
	queueSize     = 32
	rekeyOverlap  = 30 * time.Second
	writeDeadline = 5 * time.Second
)

var ErrRekey = errors.New("OpenVPN data rekey failed")

type Options struct {
	TLS            tlscontrol.Options
	Protection     control.Protection
	MaxPacketSize  int
	RekeyInterval  time.Duration
	HandshakeLimit time.Duration
}

// Session owns one authenticated OpenVPN link. Control generations share its
// transport, while current and retiring data generations have separate replay
// and nonce state.
type Session struct {
	opts   Options
	raw    transport.PacketConn
	mux    *control.Mux
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	inbound   chan []byte
	writeGate chan struct{}
	rotate    chan struct{}

	mu       sync.Mutex
	channel  *data.Channel
	info     tlscontrol.Negotiation
	keyID    uint8
	lastSent time.Time
	lastRecv time.Time

	terminal error
	closeErr error
}

// Open authenticates the initial session. On success the session owns raw.
// On failure the caller still owns raw and may close it.
func Open(ctx context.Context, raw transport.PacketConn, opts Options) (*Session, error) {
	udp := strings.HasPrefix(opts.TLS.Network, "udp")
	mux, err := control.NewMux(raw, opts.Protection, opts.MaxPacketSize, udp)
	if err != nil {
		return nil, err
	}
	var stream *control.Stream
	opened := false
	defer func() {
		if !opened {
			if stream != nil {
				stream.Close()
			}
			mux.Close()
			opts.TLS.Auth.Clear()
		}
	}()
	stream, err = mux.StartInitial()
	if err != nil {
		return nil, err
	}
	link, err := tlscontrol.Establish(ctx, stream, opts.TLS, nil)
	if err != nil {
		return nil, err
	}
	keys, err := link.DataKeys()
	if err != nil {
		return nil, err
	}
	ch, err := data.NewChannel(link.Info.PeerID, udp, keys)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	now := time.Now()
	s := &Session{
		opts: opts, raw: raw, mux: mux, ctx: lifetime, cancel: cancel, done: make(chan struct{}),
		inbound: make(chan []byte, queueSize), writeGate: make(chan struct{}, 1), rotate: make(chan struct{}, 1),
		channel: ch, info: link.Info, lastSent: now, lastRecv: now,
	}
	mux.Expect(stream, data.NextKeyID(ch.KeyID()))
	opened = true
	go s.run(link)
	return s, nil
}

func (s *Session) Info() (tlscontrol.Negotiation, uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info, s.keyID
}

func (s *Session) Done() <-chan struct{} { return s.done }

// Err returns the stable shutdown cause once the session has finished.
func (s *Session) Err() error {
	select {
	case <-s.done:
		return s.terminal
	default:
		return nil
	}
}

func (s *Session) Close() error {
	s.cancel()
	<-s.done
	return s.closeErr
}

func (s *Session) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case <-s.done:
		return 0, s.terminalError()
	case <-ctx.Done():
		return 0, ctx.Err()
	case packet := <-s.inbound:
		defer clear(packet)
		if err := s.ctx.Err(); err != nil {
			return 0, net.ErrClosed
		}
		if len(packet) > len(dst) {
			return 0, io.ErrShortBuffer
		}
		return copy(dst, packet), nil
	}
}

func (s *Session) WritePacket(ctx context.Context, packet []byte) error {
	if len(packet) > s.opts.MaxPacketSize-data.Overhead {
		return transport.ErrPacketTooLarge
	}
	if !data.IsIP(packet) {
		return data.ErrPacket
	}
	return s.write(ctx, packet)
}

func (s *Session) terminalError() error {
	if s.terminal != nil {
		return s.terminal
	}
	return net.ErrClosed
}

func (s *Session) write(ctx context.Context, plain []byte) error {
	ctx, cancel := context.WithTimeout(ctx, writeDeadline)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()

	select {
	case s.writeGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.terminalError()
	}
	defer func() { <-s.writeGate }()
	if err := ctx.Err(); err != nil {
		return err
	}

	// Serialize sealing and transport writes together. Otherwise a
	// concurrent keepalive could overtake the packet it follows on TCP.
	s.mu.Lock()
	if s.channel == nil || s.ctx.Err() != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	packet, err := s.channel.Seal(plain)
	due := s.channel.RekeyDue()
	s.mu.Unlock()
	if due {
		s.requestRekey()
	}
	if err != nil {
		if errors.Is(err, data.ErrKeyLimit) {
			s.cancel()
		}
		return err
	}
	if err := s.mux.Write(ctx, packet); err != nil {
		return err
	}
	s.mu.Lock()
	s.lastSent = time.Now()
	s.mu.Unlock()
	return nil
}

func (s *Session) requestRekey() {
	select {
	case s.rotate <- struct{}{}:
	default:
	}
}

func (s *Session) receive(wrapped []byte) {
	now := time.Now()
	s.mu.Lock()
	packet, err := s.channel.Open(wrapped, now)
	keepalive, validIP := false, false
	if err == nil {
		keepalive, validIP = data.IsKeepalive(packet), data.IsIP(packet)
		if keepalive || validIP {
			s.lastRecv = now
		}
	}
	due := err == nil && s.channel.RekeyDue()
	s.mu.Unlock()
	if err != nil {
		return
	}
	if due {
		s.requestRekey()
	}
	if keepalive || !validIP {
		clear(packet)
		return
	}
	select {
	case s.inbound <- packet:
	default:
		clear(packet)
	}
}
