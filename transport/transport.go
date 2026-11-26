// Package transport provides packet-oriented network I/O for OpenVPN.
// UDP preserves datagrams and TCP uses a two-byte length prefix.
package transport

import (
	"context"
	"errors"
)

const (
	// DefaultPacketSize is the default limit in bytes, excluding TCP framing.
	DefaultPacketSize = 16 * 1024
	// MaxPacketSize is the maximum wire length, excluding TCP framing.
	MaxPacketSize = 65535
)

var (
	// ErrEmptyPacket indicates a zero-length packet.
	ErrEmptyPacket = errors.New("empty transport packet")
	// ErrPacketTooLarge indicates a packet above the configured limit.
	ErrPacketTooLarge = errors.New("transport packet too large")
	// ErrInvalidPacketLimit indicates an invalid SocketDialer limit.
	ErrInvalidPacketLimit = errors.New("invalid transport packet limit")
	// ErrUnsupportedNetwork indicates a network other than UDP or TCP.
	ErrUnsupportedNetwork = errors.New("unsupported packet network")
)

// PacketConn exchanges complete OpenVPN protocol packets.
//
// ReadPacket reads one packet into the caller's buffer. An insufficient buffer
// discards that packet and returns io.ErrShortBuffer. On error the caller must
// ignore the buffer contents. WritePacket uses the supplied bytes only during
// the call. Neither operation retains caller-owned slices.
//
// One reader and one writer can run concurrently. Close is safe concurrently
// with both and unblocks in-flight operations. ReadPacket and WritePacket
// must honor context cancellation. A stream may close when an interrupted
// operation prevents recovery at the next packet boundary.
type PacketConn interface {
	ReadPacket(ctx context.Context, dst []byte) (int, error)
	WritePacket(ctx context.Context, packet []byte) error
	Close() error
}

// Dialer creates a packet transport for a remote endpoint. Network is udp,
// tcp or an IP-family variant. Address is a host:port value. A successful
// dial transfers ownership of the connection to the caller. Implementations
// must return promptly on context cancellation and clean up failed dials.
type Dialer interface {
	DialPacket(ctx context.Context, network, address string) (PacketConn, error)
}
