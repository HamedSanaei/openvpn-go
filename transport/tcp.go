package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
)

type tcpConn struct {
	*socket
	frame []byte
}

func (c *tcpConn) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	finish, err := c.start(ctx, c.readGate, c.conn.SetReadDeadline)
	if err != nil {
		return 0, err
	}
	defer finish()

	var header [2]byte
	n, err := io.ReadFull(c.conn, header[:])
	if err != nil {
		err = c.ioError(ctx, err)
		if n > 0 || !isContextError(err) {
			c.Close()
		}
		return 0, err
	}

	length := int(binary.BigEndian.Uint16(header[:]))
	if err := c.checkSize(length); err != nil {
		c.Close()
		return 0, err
	}
	if length > len(dst) {
		if _, err := io.CopyN(io.Discard, c.conn, int64(length)); err != nil {
			c.Close()
			return 0, c.ioError(ctx, truncatedFrame(err))
		}
		return 0, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(c.conn, dst[:length]); err != nil {
		c.Close()
		return 0, c.ioError(ctx, truncatedFrame(err))
	}
	return length, nil
}

func (c *tcpConn) WritePacket(ctx context.Context, packet []byte) error {
	if err := c.checkSize(len(packet)); err != nil {
		return err
	}
	finish, err := c.start(ctx, c.writeGate, c.conn.SetWriteDeadline)
	if err != nil {
		return err
	}
	defer finish()

	if c.frame == nil {
		c.frame = make([]byte, 2+c.limit)
	}
	binary.BigEndian.PutUint16(c.frame, uint16(len(packet)))
	copy(c.frame[2:], packet)
	frame := c.frame[:2+len(packet)]

	sent := 0
	for sent < len(frame) {
		n, err := c.conn.Write(frame[sent:])
		sent += n
		if err != nil {
			err = c.ioError(ctx, err)
			if sent > 0 || !isContextError(err) {
				c.Close()
			}
			return err
		}
		if n == 0 {
			c.Close()
			return io.ErrShortWrite
		}
	}
	return nil
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func truncatedFrame(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
