package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/observability"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
	"github.com/hamedsanaei/openvpn-go/transport"
)

const dataQueueSize = 32

// Mux separates data datagrams from reliable control traffic. The connection
// has a single reader and all writers share the same cancellable send gate.
type Mux struct {
	raw        transport.PacketConn
	protection *frameProtection
	limit      int
	chunkSize  int
	udp        bool

	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	send      chan struct{}
	data      chan []byte
	dataQueue observability.Queue
	resets    chan Reset

	mu      sync.Mutex
	lanes   [8]*lane
	local   wire.SessionID
	peer    wire.SessionID
	expect  uint8
	txKey   uint8
	readErr error
}

type Reset struct {
	KeyID uint8
	raw   []byte
}

// ControlChunkSize validates the outbound control frame budget.
func (p Protection) ControlChunkSize(limit int) (int, error) {
	c := newCodec(p, 0)
	frameLimit, header := min(limit, 1250), c.overhead()+maxControlHeader
	if frameLimit <= header || len(p.wrapped) > frameLimit-header {
		return 0, ErrProtection
	}
	return frameLimit - header, nil
}

func NewMux(packets transport.PacketConn, protection Protection, limit int, udp bool) (*Mux, error) {
	chunkSize, err := protection.ControlChunkSize(limit)
	if err != nil {
		return nil, err
	}
	c := newCodec(protection, uint32(time.Now().Unix()))
	ctx, cancel := context.WithCancel(context.Background())
	m := &Mux{
		raw: packets, limit: limit, chunkSize: chunkSize, udp: udp,
		protection: &frameProtection{codec: c},
		ctx:        ctx, cancel: cancel, done: make(chan struct{}), send: make(chan struct{}, 1),
		data: make(chan []byte, dataQueueSize), resets: make(chan Reset, 1),
	}
	go m.read()
	return m, nil
}

func (m *Mux) StartInitial() (*Stream, error) {
	var local wire.SessionID
	if _, err := rand.Read(local[:]); err != nil || local == (wire.SessionID{}) {
		return nil, ErrReliable
	}
	return m.start(0, local, wire.SessionID{}, nil)
}

func (m *Mux) Expect(stream *Stream, id uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.local, m.peer, m.expect = stream.local, stream.peer, id
}

func (m *Mux) StartRekey(id uint8, first Reset) (*Stream, error) {
	m.mu.Lock()
	local, peer, expect := m.local, m.peer, m.expect
	m.mu.Unlock()
	if id == 0 || id != expect || peer == (wire.SessionID{}) || (first.KeyID != 0 && first.KeyID != id) {
		return nil, ErrReliable
	}
	return m.start(id, local, peer, first.raw)
}

// RelayReset forwards a reset that was queued immediately before its lane was
// opened by a local rekey. TCP cannot rely on receiving another copy.
func (m *Mux) RelayReset(reset Reset) {
	if reset.KeyID == 0 {
		return
	}
	m.mu.Lock()
	l := m.lanes[reset.KeyID]
	m.mu.Unlock()
	if l != nil {
		l.deliver(reset.raw)
	}
}

func (m *Mux) start(id uint8, local, peer wire.SessionID, prepend []byte) (*Stream, error) {
	l := &lane{mux: m, id: id, input: make(chan []byte, windowSize), closed: make(chan struct{})}
	m.mu.Lock()
	if m.ctx.Err() != nil {
		m.mu.Unlock()
		return nil, ErrTransport
	}
	if m.lanes[id] != nil {
		m.mu.Unlock()
		return nil, ErrReliable
	}
	if prepend != nil {
		l.input <- prepend
	}
	m.lanes[id] = l
	m.txKey = id
	m.mu.Unlock()

	d := newDriver(l, m.protection, m.udp)
	d.local, d.peer, d.keyID = local, peer, id
	return startStream(d, m.limit, m.chunkSize), nil
}

func (m *Mux) Data() <-chan []byte { return m.data }

func (m *Mux) DataQueueStats() observability.QueueStats { return m.dataQueue.Stats() }

func (m *Mux) Resets() <-chan Reset { return m.resets }

func (m *Mux) Done() <-chan struct{} { return m.done }

func (m *Mux) Close() {
	m.cancel()
	<-m.done
}

func (m *Mux) Write(ctx context.Context, packet []byte) error {
	return m.write(ctx, packet, nil)
}

func (m *Mux) write(ctx context.Context, packet []byte, control *lane) error {
	select {
	case m.send <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-m.ctx.Done():
		return m.terminalError()
	}
	defer func() { <-m.send }()
	if m.ctx.Err() != nil {
		return m.terminalError()
	}
	if control != nil {
		m.mu.Lock()
		current := m.txKey == control.id && m.lanes[control.id] == control
		m.mu.Unlock()
		if !current {
			return nil
		}
	}
	return m.raw.WritePacket(ctx, packet)
}

func (m *Mux) terminalError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readErr != nil {
		return m.readErr
	}
	return net.ErrClosed
}

func (m *Mux) read() {
	defer close(m.done)
	defer m.cancel()
	buffer := make([]byte, m.limit)
	for m.ctx.Err() == nil {
		n, err := m.raw.ReadPacket(m.ctx, buffer)
		if err != nil {
			if m.udp && discardedDatagram(err) {
				continue
			}
			m.mu.Lock()
			m.readErr = controlIOError(m.ctx, err)
			m.mu.Unlock()
			return
		}
		if n < 1 || n > len(buffer) {
			continue
		}
		packet := buffer[:n]
		h, err := wire.ParseHeader(packet)
		if err != nil {
			continue
		}
		if h.IsData() {
			if h.Opcode == wire.DataV2 {
				depth := len(m.data)
				if depth == cap(m.data) {
					m.dataQueue.Drop(depth)
				} else {
					m.data <- bytes.Clone(packet)
					m.dataQueue.Observe(depth + 1)
				}
			}
			continue
		}

		m.mu.Lock()
		l, expected, local, peer := m.lanes[h.KeyID], m.expect, m.local, m.peer
		m.mu.Unlock()
		if l != nil {
			l.deliver(packet)
		} else if h.KeyID != 0 && h.KeyID == expected && h.Opcode == wire.SoftReset && len(m.resets) == 0 {
			p, counter, timestamp, err := m.protection.open(packet)
			if err == nil && p.ID == 0 && len(p.Payload) == 0 && p.Sender == peer &&
				(p.ACKCount == 0 || p.ACKTarget == local) && m.protection.mayAccept(counter, timestamp) {
				m.mu.Lock()
				if h.KeyID == m.expect {
					m.txKey = h.KeyID
				}
				m.mu.Unlock()
				m.resets <- Reset{KeyID: h.KeyID, raw: bytes.Clone(packet)}
			}
		}
	}
}

type lane struct {
	mux    *Mux
	id     uint8
	input  chan []byte
	closed chan struct{}
	once   sync.Once
}

func (l *lane) deliver(packet []byte) {
	if l.mux.udp && len(l.input) == cap(l.input) {
		return
	}
	select {
	case l.input <- bytes.Clone(packet):
	case <-l.closed:
	case <-l.mux.ctx.Done():
	}
}

func (l *lane) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	select {
	case in := <-l.input:
		if len(in) > len(dst) {
			return 0, io.ErrShortBuffer
		}
		return copy(dst, in), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-l.closed:
		return 0, net.ErrClosed
	case <-l.mux.ctx.Done():
		return 0, l.mux.terminalError()
	}
}

func (l *lane) WritePacket(ctx context.Context, packet []byte) error {
	return l.mux.write(ctx, packet, l)
}

func (l *lane) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.mux.mu.Lock()
		l.mux.lanes[l.id] = nil
		l.mux.mu.Unlock()
	})
	return nil
}
