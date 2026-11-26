package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSocketDialerTCP(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := (SocketDialer{}).DialPacket(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	peer.SetDeadline(time.Now().Add(3 * time.Second))

	if err := conn.WritePacket(ctx, []byte{0x30, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	var wire [5]byte
	if _, err := io.ReadFull(peer, wire[:]); err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 3, 0x30, 0x01, 0x02}; !bytes.Equal(wire[:], want) {
		t.Fatalf("wire bytes = %x, want %x", wire, want)
	}

	if _, err := peer.Write([]byte{0, 1, 0x31, 0, 2, 0x32, 0x33}); err != nil {
		t.Fatal(err)
	}
	assertPacket(t, ctx, conn, []byte{0x31})
	assertPacket(t, ctx, conn, []byte{0x32, 0x33})
}

func TestSocketDialerUDP(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	server.SetDeadline(time.Now().Add(3 * time.Second))

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := (SocketDialer{MaxPacketSize: 8}).DialPacket(ctx, "udp4", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	if err := conn.WritePacket(ctx, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	var dst [16]byte
	n, remote, err := server.ReadFromUDP(dst[:])
	if err != nil || !bytes.Equal(dst[:n], []byte{1, 2, 3}) {
		t.Fatalf("server read = %x, %v", dst[:n], err)
	}

	cases := []struct {
		name   string
		packet []byte
		dst    []byte
		want   error
	}{
		{name: "empty", dst: dst[:], want: ErrEmptyPacket},
		{name: "short buffer", packet: []byte{1, 2, 3}, dst: dst[:2], want: io.ErrShortBuffer},
		{name: "limit plus one", packet: make([]byte, 9), dst: dst[:], want: ErrPacketTooLarge},
		{name: "large datagram", packet: make([]byte, 60000), dst: dst[:], want: ErrPacketTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := server.WriteToUDP(tc.packet, remote); err != nil {
				t.Fatal(err)
			}
			if n, err := conn.ReadPacket(ctx, tc.dst); n != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("ReadPacket = %d, %v; want 0, %v", n, err, tc.want)
			}
		})
	}

	first := bytes.Repeat([]byte{6}, 8)
	for _, packet := range [][]byte{first, {8, 9}} {
		if _, err := server.WriteToUDP(packet, remote); err != nil {
			t.Fatal(err)
		}
	}
	assertPacket(t, ctx, conn, first)
	assertPacket(t, ctx, conn, []byte{8, 9})
	assertWriteLimits(t, ctx, conn, 8)
}

func TestSocketDialerValidation(t *testing.T) {
	dialer := SocketDialer{}
	if _, err := dialer.DialPacket(t.Context(), "unix", "invalid"); !errors.Is(err, ErrUnsupportedNetwork) {
		t.Fatalf("unsupported network error = %v", err)
	}
	for _, limit := range []int{-1, MaxPacketSize + 1} {
		dialer.MaxPacketSize = limit
		if _, err := dialer.DialPacket(t.Context(), "tcp", "invalid"); !errors.Is(err, ErrInvalidPacketLimit) {
			t.Fatalf("invalid limit error = %v", err)
		}
	}
}

func assertPacket(t *testing.T, ctx context.Context, conn PacketConn, want []byte) {
	t.Helper()
	dst := make([]byte, len(want))
	n, err := conn.ReadPacket(ctx, dst)
	if err != nil || n != len(want) || !bytes.Equal(dst, want) {
		t.Fatalf("ReadPacket = %x, %d, %v; want %x", dst, n, err, want)
	}
}

func assertWriteLimits(t *testing.T, ctx context.Context, conn PacketConn, limit int) {
	t.Helper()
	if err := conn.WritePacket(ctx, nil); !errors.Is(err, ErrEmptyPacket) {
		t.Fatalf("empty write error = %v", err)
	}
	if err := conn.WritePacket(ctx, make([]byte, limit+1)); !errors.Is(err, ErrPacketTooLarge) {
		t.Fatalf("oversize write error = %v", err)
	}
}

func newPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() { local.Close() })
	t.Cleanup(func() { peer.Close() })
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	return local, peer
}

func waitError(t *testing.T, result <-chan error, want error) {
	t.Helper()
	select {
	case err := <-result:
		if !errors.Is(err, want) {
			t.Fatalf("error = %v; want %v", err, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("operation stayed blocked")
	}
}

type observedConn struct {
	net.Conn
	reading chan struct{}
	writing chan struct{}
	read    sync.Once
	write   sync.Once
}

func (c *observedConn) Read(b []byte) (int, error) {
	c.read.Do(func() { close(c.reading) })
	return c.Conn.Read(b)
}

func (c *observedConn) Write(b []byte) (int, error) {
	c.write.Do(func() { close(c.writing) })
	return c.Conn.Write(b)
}
