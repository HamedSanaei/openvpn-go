package testkit

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/hamedsanaei/openvpn-go/transport"
)

// DialerFunc adapts a scripted dial to the public transport contract.
type DialerFunc func(context.Context, string, string) (transport.PacketConn, error)

func (f DialerFunc) DialPacket(ctx context.Context, network, address string) (transport.PacketConn, error) {
	return f(ctx, network, address)
}

type pipeState struct {
	done chan struct{}
	once sync.Once
}

// PacketPipe returns two in-memory packet endpoints. Each direction buffers
// at most capacity packets, and a write copies its input. Closing either end
// unblocks both endpoints. A zero capacity is useful for blocking I/O tests.
func PacketPipe(capacity, limit int) (transport.PacketConn, transport.PacketConn) {
	if capacity < 0 || limit < 1 || limit > transport.MaxPacketSize {
		panic("invalid test packet pipe capacity or limit")
	}
	state := &pipeState{done: make(chan struct{})}
	first := make(chan []byte, capacity)
	second := make(chan []byte, capacity)
	return &packetPipe{state: state, read: first, write: second, limit: limit},
		&packetPipe{state: state, read: second, write: first, limit: limit}
}

type packetPipe struct {
	state *pipeState
	read  <-chan []byte
	write chan<- []byte
	limit int
}

func (p *packetPipe) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	if err := p.ready(ctx); err != nil {
		return 0, err
	}
	select {
	case <-p.state.done:
		return 0, net.ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	case packet := <-p.read:
		if len(packet) > len(dst) {
			return 0, io.ErrShortBuffer
		}
		return copy(dst, packet), nil
	}
}

func (p *packetPipe) WritePacket(ctx context.Context, packet []byte) error {
	if len(packet) == 0 {
		return transport.ErrEmptyPacket
	}
	if len(packet) > p.limit {
		return transport.ErrPacketTooLarge
	}
	if err := p.ready(ctx); err != nil {
		return err
	}
	packet = append([]byte(nil), packet...)
	select {
	case <-p.state.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case p.write <- packet:
		return nil
	}
}

func (p *packetPipe) ready(ctx context.Context) error {
	select {
	case <-p.state.done:
		return net.ErrClosed
	default:
		return ctx.Err()
	}
}

func (p *packetPipe) Close() error {
	p.state.once.Do(func() { close(p.state.done) })
	return nil
}
