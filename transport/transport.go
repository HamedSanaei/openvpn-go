// Package transport defines packet-oriented network transports for OpenVPN.
//
// UDP adapters preserve datagram boundaries. TCP adapters must implement the
// OpenVPN length-prefixed framing and expose complete packets to the protocol
// engine. Implementations must document cancellation, buffer ownership and
// Close semantics.
package transport

import "context"

// PacketConn reads and writes complete OpenVPN protocol packets.
//
// A successful ReadPacket returns one complete packet. Implementations must
// reject oversized frames and must make blocked operations terminate when the
// context is cancelled or the connection is closed.
type PacketConn interface {
	ReadPacket(ctx context.Context, dst []byte) (int, error)
	WritePacket(ctx context.Context, packet []byte) error
	Close() error
}

// Dialer creates a packet transport for a remote endpoint. Network is expected
// to be udp or tcp; address is a host:port value. Custom dialers may use these
// fields as hints when the transport is supplied by a proxy or embedding app.
type Dialer interface {
	DialPacket(ctx context.Context, network, address string) (PacketConn, error)
}
