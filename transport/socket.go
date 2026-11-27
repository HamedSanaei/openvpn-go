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

	udp := network == "udp" || network == "udp4" || network == "udp6"
	_, nativeDatagram := conn.(*net.UDPConn)
	var peerIP netip.Addr
	if d.dial == nil || udp && nativeDatagram {
		switch addr := conn.RemoteAddr().(type) {
		case *net.TCPAddr:
			peerIP = addr.AddrPort().Addr().Unmap()
		case *net.UDPAddr:
			peerIP = addr.AddrPort().Addr().Unmap()
		}
	}
	if udp && (d.dial == nil || nativeDatagram) {
		// IPv4's total length includes its header. IPv6's payload length
		// only includes the UDP header in the absence of extension headers.
		maxPayload := 65507
		if peerIP.Is6() {
			maxPayload = 65527
		}
		limit = min(limit, maxPayload)
	}
	socket := newSocket(conn, limit)
	socket.peerIP = peerIP
	if udp {
		return &udpConn{socket: socket}, nil
	}
	return &tcpConn{socket: socket}, nil
}

type socket struct {
	conn      net.Conn
	limit     int
	read      socketDirection
	write     socketDirection
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
	peerIP    netip.Addr
}

// PeerIP reports the VPN peer for native sockets. It is unset for custom streams.
func (s *socket) PeerIP() netip.Addr { return s.peerIP }

// PacketSizeLimit reports the adapter's absolute frame ceiling before path MTU limits.
func (s *socket) PacketSizeLimit() int { return s.limit }

func newSocket(conn net.Conn, limit int) *socket {
	return &socket{
		conn:   conn,
		limit:  limit,
		read:   newSocketDirection(conn.SetReadDeadline),
		write:  newSocketDirection(conn.SetWriteDeadline),
		closed: make(chan struct{}),
	}
}

func (s *socket) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.closeErr = s.conn.Close()
	})
	return s.closeErr
}

type socketDirection struct {
	gate        chan struct{}
	interrupted chan struct{}
	setDeadline func(time.Time) error
}

func newSocketDirection(setDeadline func(time.Time) error) socketDirection {
	return socketDirection{
		gate: make(chan struct{}, 1), interrupted: make(chan struct{}, 1), setDeadline: setDeadline,
	}
}

type socketOperation struct {
	socket *socket
	side   *socketDirection
	stop   func() bool
}

func (s *socket) start(ctx context.Context, side *socketDirection) (socketOperation, error) {
	select {
	case side.gate <- struct{}{}:
	case <-s.closed:
		return socketOperation{}, net.ErrClosed
	case <-ctx.Done():
		return socketOperation{}, ctx.Err()
	}

	if err := s.stateError(ctx); err != nil {
		<-side.gate
		return socketOperation{}, err
	}
	op := socketOperation{socket: s, side: side}
	if ctx.Done() != nil {
		op.stop = context.AfterFunc(ctx, func() {
			if err := side.setDeadline(time.Now()); err != nil {
				s.Close()
			}
			side.interrupted <- struct{}{}
		})
	}
	return op, nil
}

func (op socketOperation) finish() {
	if op.stop != nil && !op.stop() {
		// The direction remains owned until its own callback completes and
		// its deadline is reset, so the ticket cannot reach the next call.
		<-op.side.interrupted
		if err := op.side.setDeadline(time.Time{}); err != nil {
			op.socket.Close()
		}
	}
	<-op.side.gate
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
