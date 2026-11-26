package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
)

func FuzzTCPFrame(f *testing.F) {
	f.Add([]byte{}, uint16(8))
	f.Add([]byte{0, 0}, uint16(8))
	f.Add([]byte{0}, uint16(8))
	f.Add([]byte{0, 2, 10}, uint16(8))
	f.Add([]byte{0, 2, 10, 11, 0, 1, 12}, uint16(1))
	f.Add([]byte{16, 1}, uint16(4096))
	f.Fuzz(func(t *testing.T, raw []byte, destination uint16) {
		const limit = 4096
		if len(raw) > 4*limit {
			return
		}
		ctx := context.Background()
		source := &frameReader{Reader: bytes.NewReader(raw)}
		conn := &tcpConn{socket: newSocket(source, limit)}
		defer conn.Close()
		buf := make([]byte, min(int(destination), limit))
		for {
			n, err := conn.ReadPacket(ctx, buf)
			if len(raw) < 2 {
				want := io.ErrUnexpectedEOF
				if len(raw) == 0 {
					want = io.EOF
				}
				if n != 0 || !errors.Is(err, want) || !source.closed {
					t.Fatal("incomplete header did not close the transport")
				}
				return
			}
			size := int(binary.BigEndian.Uint16(raw))
			raw = raw[2:]
			var want error
			switch {
			case size == 0:
				want = ErrEmptyPacket
			case size > limit:
				want = ErrPacketTooLarge
			case size > len(raw):
				want = io.ErrUnexpectedEOF
			case size > len(buf):
				want = io.ErrShortBuffer
			}
			switch want {
			case nil:
				if err != nil || n != size || !bytes.Equal(buf[:n], raw[:size]) {
					t.Fatal("TCP decoder changed packet boundaries")
				}
			case io.ErrShortBuffer:
				if n != 0 || !errors.Is(err, want) || source.closed {
					t.Fatal("short destination lost frame synchronization")
				}
			default:
				if n != 0 || !errors.Is(err, want) || !source.closed {
					t.Fatal("invalid frame did not close the transport")
				}
				return
			}
			raw = raw[size:]
		}
	})
}

type frameReader struct {
	net.Conn
	*bytes.Reader
	closed bool
}

func (r *frameReader) Read(p []byte) (int, error) { return r.Reader.Read(p) }
func (r *frameReader) Close() error {
	r.closed = true
	return nil
}
