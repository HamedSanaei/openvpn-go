// Package tunnel defines the packet interface between the OpenVPN client and
// an embedding application. TUN device creation, routing, DNS and privileges
// belong to the application adapter.
package tunnel

import "context"

// PacketConn is a bidirectional IP packet source and sink.
//
// Each read and write exchanges one complete IP packet. A short read buffer
// discards one packet and returns io.ErrShortBuffer. The caller must ignore the
// buffer contents on error. Implementations do not retain caller-owned slices.
//
// One reader and one writer can run concurrently. Both must return promptly
// on context cancellation. Close is safe concurrently with packet operations,
// releases the adapter's resources and unblocks I/O. A client Run call borrows
// the tunnel for its duration. The embedding application owns Close.
type PacketConn interface {
	ReadPacket(ctx context.Context, dst []byte) (int, error)
	WritePacket(ctx context.Context, packet []byte) error
	Close() error
}
