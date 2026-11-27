package transport

import (
	"context"
	"io"
)

type udpConn struct {
	*socket
	datagram []byte
}

func (c *udpConn) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	op, err := c.start(ctx, &c.read)
	if err != nil {
		return 0, err
	}
	defer op.finish()

	// A buffer large enough for a full UDP datagram lets us distinguish
	// oversize packets from short caller buffers across socket platforms.
	if c.datagram == nil {
		c.datagram = make([]byte, MaxPacketSize+1)
	}
	n, err := c.conn.Read(c.datagram)
	if err != nil {
		return 0, c.ioError(ctx, err)
	}
	if err := c.checkSize(n); err != nil {
		return 0, err
	}
	if n > len(dst) {
		return 0, io.ErrShortBuffer
	}
	return copy(dst, c.datagram[:n]), nil
}

func (c *udpConn) WritePacket(ctx context.Context, packet []byte) error {
	if err := c.checkSize(len(packet)); err != nil {
		return err
	}
	op, err := c.start(ctx, &c.write)
	if err != nil {
		return err
	}
	defer op.finish()

	n, err := c.conn.Write(packet)
	if err != nil {
		return c.ioError(ctx, err)
	}
	if n != len(packet) {
		return io.ErrShortWrite
	}
	return nil
}
