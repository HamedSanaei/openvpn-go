// Package tunnel defines the packet interface between the OpenVPN client and
// an embedding application.
//
// The core exchanges IP packets. TUN device creation, route changes, DNS
// configuration and privilege management are intentionally outside this
// package and must be implemented by a platform or application adapter.
package tunnel

import "context"

// PacketConn is a packet source/sink supplied by the embedding application.
// Each read and write represents one complete IP packet, not a byte stream.
type PacketConn interface {
	ReadPacket(ctx context.Context, dst []byte) (int, error)
	WritePacket(ctx context.Context, packet []byte) error
	Close() error
}
