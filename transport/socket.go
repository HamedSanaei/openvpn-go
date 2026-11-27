package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// SocketDialer dials connected UDP datagram sockets and framed TCP streams.
// Its zero value uses DefaultPacketSize. Set MaxPacketSize to change the
// per-packet limit in both directions.
type SocketDialer struct {
	MaxPacketSize int
}

// DialPacket opens a socket for one endpoint.
func (d SocketDialer) DialPacket(ctx context.Context, network, address string) (PacketConn, error) {
	return socketDialer{SocketDialer: d}.DialPacket(ctx, network, address)
}

// WithDialContext uses dial to open an already connected socket or proxy
// stream for the selected remote. A nil function uses net.Dialer. TCP
// requires stream semantics and UDP requires datagram semantics. The dial
// must honor context cancellation, and the connection must support deadlines.
func (d SocketDialer) WithDialContext(dial func(context.Context, string, string) (net.Conn, error)) Dialer {
	return socketDialer{SocketDialer: d, dial: dial}
}

type socketDialer struct {
	SocketDialer
	dial      func(context.Context, string, string) (net.Conn, error)
	localAddr net.Addr
}

// WithLocalAddr uses a native socket bound to the supplied source address.
func (d SocketDialer) WithLocalAddr(addr net.Addr) Dialer {
	return socketDialer{SocketDialer: d, localAddr: addr}
}

func (d socketDialer) DialPacket(ctx context.Context, network, address string) (PacketConn, error) {
	limit := d.MaxPacketSize
	if limit < 0 || limit > MaxPacketSize {
		return nil, ErrInvalidPacketLimit
	}
	if limit == 0 {
		limit = DefaultPacketSize
	}

	switch network {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
	default:
		return nil, ErrUnsupportedNetwork
	}

	dial := d.dial
	if dial == nil {
		dial = (&net.Dialer{LocalAddr: d.localAddr}).DialContext
	}
	conn, err := dial(ctx, network, address)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}
	if conn == nil {
		return nil, ErrInvalidConnection
	}

	socket := newSocket(conn, limit)
	if d.dial == nil {
		switch addr := conn.RemoteAddr().(type) {
		case *net.TCPAddr:
			socket.peerIP = addr.AddrPort().Addr().Unmap()
		case *net.UDPAddr:
			socket.peerIP = addr.AddrPort().Addr().Unmap()
		}
	}
	if network == "udp" || network == "udp4" || network == "udp6" {
		return &udpConn{socket: socket}, nil
	}
	return &tcpConn{socket: socket}, nil
}

type socket struct {
	conn      net.Conn
	limit     int
	readGate  chan struct{}
	writeGate chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
	peerIP    netip.Addr
}

// PeerIP reports the VPN peer for native sockets. It is unset for custom streams.
func (s *socket) PeerIP() netip.Addr { return s.peerIP }

func newSocket(conn net.Conn, limit int) *socket {
	return &socket{
		conn:      conn,
		limit:     limit,
		readGate:  make(chan struct{}, 1),
		writeGate: make(chan struct{}, 1),
		closed:    make(chan struct{}),
	}
}

func (s *socket) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.closeErr = s.conn.Close()
	})
	return s.closeErr
}

func (s *socket) start(ctx context.Context, gate chan struct{}, setDeadline func(time.Time) error) (func(), error) {
	select {
	case gate <- struct{}{}:
	case <-s.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if err := s.stateError(ctx); err != nil {
		<-gate
		return nil, err
	}
	if ctx.Done() == nil {
		return func() { <-gate }, nil
	}

	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		if err := setDeadline(time.Now()); err != nil {
			s.Close()
		}
	})
	return func() {
		if !stop() {
			// Wait for the callback before resetting the deadline. The next
			// operation on this side of the socket starts with a clean slate.
			<-interrupted
			if err := setDeadline(time.Time{}); err != nil {
				s.Close()
			}
		}
		<-gate
	}, nil
}

func (s *socket) stateError(ctx context.Context) error {
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
		return ctx.Err()
	}
}

func (s *socket) ioError(ctx context.Context, err error) error {
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, io.ErrClosedPipe) {
		select {
		case <-s.closed:
			return net.ErrClosed
		default:
		}
	}
	return err
}

func (s *socket) checkSize(size int) error {
	switch {
	case size == 0:
		return ErrEmptyPacket
	case size > s.limit:
		return ErrPacketTooLarge
	default:
		return nil
	}
}
