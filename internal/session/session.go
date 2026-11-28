package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/observability"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

const (
	rekeyOverlap  = 30 * time.Second
	writeDeadline = 5 * time.Second
)

var ErrRekey = errors.New("OpenVPN data rekey failed")

type Options struct {
	TLS              tlscontrol.Options
	Protection       control.Protection
	MaxPacketSize    int
	RekeyInterval    time.Duration
	HandshakeLimit   time.Duration
	TunnelMTU        int
	FragmentSize     int
	ReceiveQueueSize int
	AcquireHandshake func(context.Context) (func(), error)
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

	inbound      chan []byte
	inboundQueue observability.Queue
	earlyDrops   atomic.Uint64
	keyExhausted atomic.Bool
	writeGate    chan struct{}
	writeBuffer  []byte // Accessed only by the write gate owner.
	rotate       chan struct{}
	notify       sync.Once
	packetMTU    int
	fragments    *fragmenter

	mu                       sync.Mutex
	channel                  *data.Channel
	link                     *tlscontrol.Link
	info                     tlscontrol.Negotiation
	keyID                    uint8
	lastSent                 time.Time
	lastRecv                 time.Time
	rekeys                   *rekeyHistory
	rate                     keyConsumptionRate
	awaitingPeerKey          bool
	retiringReceiveExhausted bool

	terminal error
	closeErr error
}

// Open authenticates the initial session. On success the session owns raw.
// On failure the caller still owns raw and may close it.
func Open(ctx context.Context, raw transport.PacketConn, opts Options) (*Session, error) {
	udp := strings.HasPrefix(opts.TLS.Network, "udp")
	frameLimit, mtu, fragments, err := packetBudget(raw, opts, udp)
	if err != nil {
		return nil, err
	}
	if opts.TunnelMTU != 0 || mtu < 1500 {
		opts.TLS.TunnelMTU = mtu
	}
	mux, err := control.NewMuxForDataFormat(raw, opts.Protection, frameLimit, udp, opts.ReceiveQueueSize, opts.TLS.FixedDataV1)
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
	observability.Enter(ctx, observability.PhaseResetACK)
	stream, err = mux.StartInitial()
	if err != nil {
		return nil, err
	}
	link, err := tlscontrol.Establish(ctx, stream, opts.TLS, nil)
	if err != nil {
		return nil, err
	}
	observability.Enter(ctx, observability.PhaseDataSetup)
	if link.Info.Tunnel.MTU != 0 {
		mtu = min(mtu, int(link.Info.Tunnel.MTU))
	}
	if link.Info.Tunnel.MTU != 0 || opts.TunnelMTU != 0 || fragments != nil {
		link.Info.Tunnel.MTU = uint16(mtu)
	}
	if link.Info.Tunnel.IPv6.IsValid() && mtu < 1280 {
		return nil, tlscontrol.ErrNegotiation
	}
	link.Info.PacketMTU = mtu
	opts.TunnelMTU = int(link.Info.Tunnel.MTU)
	observability.Enter(ctx, observability.PhaseKeyDerivation)
	keys, err := link.DataKeys()
	if err != nil {
		return nil, err
	}
	observability.Enter(ctx, observability.PhaseDataSetup)
	ch, err := data.NewChannelForFormat(link.Info.PeerID, udp, keys, link.Info.DataV1)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	now := time.Now()
	s := &Session{
		opts: opts, raw: raw, mux: mux, ctx: lifetime, cancel: cancel, done: make(chan struct{}),
		inbound: make(chan []byte, cap(mux.Data())), writeGate: make(chan struct{}, 1), rotate: make(chan struct{}, 1),
		channel: ch, link: link, packetMTU: mtu, fragments: fragments, info: link.Info, lastSent: now, lastRecv: now,
	}
	s.rate.observe(now, ch.KeyUsage(), opts.HandshakeLimit)
	mux.Expect(stream, data.NextKeyID(ch.KeyID()))
	opened = true
	go s.run(link)
	return s, nil
}

// ValidatePacketBudget checks the known frame and tunnel limits before dialing.
// The connected adapter can impose a smaller runtime limit.
func ValidatePacketBudget(opts Options, udp bool) error {
	_, _, _, err := packetBudget(nil, opts, udp)
	return err
}

// packetBudget computes the outer frame limit and the local whole-packet MTU.
func packetBudget(raw transport.PacketConn, opts Options, udp bool) (int, int, *fragmenter, error) {
	frameLimit := opts.MaxPacketSize
	if conn, ok := raw.(interface{ PacketSizeLimit() int }); ok {
		if limit := conn.PacketSizeLimit(); limit > 0 {
			frameLimit = min(frameLimit, limit)
		}
	}
	mtu := frameLimit - data.Overhead
	var fragments *fragmenter
	if opts.FragmentSize != 0 {
		limit := min(opts.FragmentSize, frameLimit)
		if !udp || limit < fragmentHeaderSize+data.Overhead+68+1 {
			return 0, 0, nil, tlscontrol.ErrNegotiation
		}
		fragments = &fragmenter{chunkSize: (limit - fragmentHeaderSize - data.Overhead) &^ 3}
		mtu = min(opts.MaxPacketSize, fragments.chunkSize*maxFragments-1)
	}
	if opts.TunnelMTU != 0 {
		mtu = min(mtu, opts.TunnelMTU)
	}
	if mtu < 68 {
		return 0, 0, nil, tlscontrol.ErrNegotiation
	}
	return frameLimit, mtu, fragments, nil
}

func (s *Session) Info() (tlscontrol.Negotiation, uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info, s.keyID
}

func (s *Session) Done() <-chan struct{} { return s.done }

func (s *Session) QueueStats() (observability.QueueStats, observability.QueueStats) {
	return s.mux.DataQueueStats(), s.inboundQueue.Stats()
}

func (s *Session) EarlyRekeyDrops() uint64 { return s.earlyDrops.Load() }

// CleanupError is stable after Done closes.
func (s *Session) CleanupError() error {
	select {
	case <-s.done:
		return s.closeErr
	default:
		return nil
	}
}

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

// CloseGracefully makes one bounded attempt to notify a negotiated UDP peer.
func (s *Session) CloseGracefully() error {
	s.notify.Do(func() {
		s.mu.Lock()
		link := s.link
		s.mu.Unlock()
		if link == nil || !link.Info.ExitNotify || s.ctx.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, 250*time.Millisecond)
		defer cancel()
		_ = link.NotifyExit(ctx)
	})
	return s.Close()
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
	if len(packet) > s.packetMTU {
		return tunnel.ErrMTUExceeded
	}
	if !data.IsIP(packet) {
		return tunnel.ErrInvalidPacket
	}
	return s.write(ctx, packet, false)
}

func (s *Session) terminalError() error {
	if s.terminal != nil {
		return s.terminal
	}
	return net.ErrClosed
}

func (s *Session) write(ctx context.Context, plain []byte, onlyIdle bool) error {
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
	if onlyIdle && (s.info.PingInterval <= 0 || time.Since(s.lastSent) < s.info.PingInterval) {
		s.mu.Unlock()
		return nil
	}
	if s.info.Tunnel.BlockIPv6 && len(plain) != 0 && plain[0]>>4 == 6 {
		s.mu.Unlock()
		return tunnel.ErrInvalidPacket
	}
	var packets [][]byte
	var err error
	if s.fragments != nil {
		packets, err = s.fragments.seal(s.channel, plain)
	} else {
		if s.writeBuffer == nil {
			s.writeBuffer = make([]byte, 0, s.packetMTU+data.Overhead)
		}
		var packet []byte
		packet, err = s.channel.SealInto(s.writeBuffer, plain)
		packets = [][]byte{packet}
	}
	due := s.rekeyDueLocked()
	s.mu.Unlock()
	if due {
		s.requestRekey()
	}
	if err != nil {
		if errors.Is(err, data.ErrKeyLimit) {
			s.keyExhausted.Store(true)
			s.cancel()
		}
		return err
	}
	for _, packet := range packets {
		if err := s.mux.Write(ctx, packet); err != nil {
			return err
		}
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

func (s *Session) receive(wrapped []byte) error {
	now := time.Now()
	s.mu.Lock()
	packet, epoch, err := s.channel.OpenOwned(wrapped, now)
	keepalive, validIP := false, false
	if err == nil {
		if s.awaitingPeerKey {
			if epoch == s.channel.KeyUsage().Epoch {
				s.channel.ShortenRetiringOverlap(now.Add(rekeyOverlap))
				s.awaitingPeerKey, s.retiringReceiveExhausted = false, false
			} else if s.channel.RetiringReceiveExhausted() {
				s.retiringReceiveExhausted = true
			}
		}
		keepalive = data.IsKeepalive(packet)
		// Some legacy peers also send bare encrypted keepalives.
		if !keepalive && s.fragments != nil {
			packet = s.fragments.open(wrapped, packet, epoch, s.packetMTU, now)
			keepalive = data.IsKeepalive(packet)
		}
		validIP = len(packet) <= s.packetMTU && data.IsIP(packet) && !(s.info.Tunnel.BlockIPv6 && packet[0]>>4 == 6)
		if keepalive || validIP {
			s.lastRecv = now
		}
	}
	due := err == nil && s.rekeyDueLocked()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if due {
		s.requestRekey()
	}
	if keepalive || !validIP {
		clear(packet)
		return nil
	}
	select {
	case s.inbound <- packet:
		s.inboundQueue.Observe(max(1, len(s.inbound)))
	default:
		s.inboundQueue.Drop(cap(s.inbound))
		clear(packet)
	}
	return nil
}
