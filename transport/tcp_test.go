package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPFragmentedFramesAndShortDestination(t *testing.T) {
	local, peer := newPipe(t)
	conn := &tcpConn{socket: newSocket(local, 8)}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	sent := make(chan error, 1)
	go func() {
		for _, part := range [][]byte{{0}, {3, 1}, {2}, {3, 0, 1, 4, 0}, {2, 5, 6}} {
			if _, err := peer.Write(part); err != nil {
				sent <- err
				return
			}
		}
		sent <- nil
	}()

	if n, err := conn.ReadPacket(ctx, make([]byte, 2)); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short ReadPacket = %d, %v", n, err)
	}
	assertPacket(t, ctx, conn, []byte{4})
	assertPacket(t, ctx, conn, []byte{5, 6})
	waitError(t, sent, nil)
}

func TestTCPInvalidFrameClosesStream(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bytes []byte
		want  error
	}{
		{"empty", []byte{0, 0}, ErrEmptyPacket},
		{"oversize", []byte{0, 9}, ErrPacketTooLarge},
		{"prefix EOF", []byte{0}, io.ErrUnexpectedEOF},
		{"body EOF", []byte{0, 3, 1}, io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local, peer := newPipe(t)
			conn := &tcpConn{socket: newSocket(local, 8)}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			go func() {
				peer.Write(tc.bytes)
				peer.Close()
			}()

			if n, err := conn.ReadPacket(ctx, make([]byte, 8)); n != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("ReadPacket = %d, %v; want 0, %v", n, err, tc.want)
			}
			if err := conn.WritePacket(ctx, []byte{1}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after malformed frame = %v", err)
			}
		})
	}
}

type shortWriter struct{ net.Conn }

func (w shortWriter) Write(b []byte) (int, error) {
	return w.Conn.Write(b[:1])
}

func TestTCPMaximumFrameAndShortWrites(t *testing.T) {
	t.Run("short writes", func(t *testing.T) {
		local, peer := newPipe(t)
		conn := &tcpConn{socket: newSocket(shortWriter{local}, 8)}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()

		want := []byte{0, 4, 1, 2, 3, 4}
		done := make(chan error, 1)
		go func() { done <- conn.WritePacket(ctx, want[2:]) }()
		got := make([]byte, len(want))
		if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("frame = %x, %v; want %x", got, err, want)
		}
		waitError(t, done, nil)
		assertWriteLimits(t, ctx, conn, 8)
	})

	t.Run("maximum wire size", func(t *testing.T) {
		first, second := newPipe(t)
		a := &tcpConn{socket: newSocket(first, MaxPacketSize)}
		b := &tcpConn{socket: newSocket(second, MaxPacketSize)}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()

		packet := bytes.Repeat([]byte{0xd5}, MaxPacketSize)
		done := make(chan error, 1)
		go func() { done <- a.WritePacket(ctx, packet) }()
		assertPacket(t, ctx, b, packet)
		waitError(t, done, nil)
	})
}

func TestTCPReadCancellationAndDeadlineReset(t *testing.T) {
	local, peer := newPipe(t)
	observed := &observedConn{Conn: local, reading: make(chan struct{})}
	conn := &tcpConn{socket: newSocket(observed, 8)}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := conn.ReadPacket(ctx, make([]byte, 8))
		result <- err
	}()
	select {
	case <-observed.reading:
	case <-time.After(3 * time.Second):
		t.Fatal("read did not start")
	}
	cancel()
	waitError(t, result, context.Canceled)

	done := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte{0, 1, 8})
		done <- err
	}()
	assertPacket(t, t.Context(), conn, []byte{8})
	waitError(t, done, nil)
}

func TestTCPPartialFrameCancellationCloses(t *testing.T) {
	local, peer := newPipe(t)
	conn := &tcpConn{socket: newSocket(local, 8)}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := conn.ReadPacket(ctx, make([]byte, 8))
		result <- err
	}()
	if _, err := peer.Write([]byte{0, 4, 1}); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitError(t, result, context.Canceled)
	if _, err := conn.ReadPacket(t.Context(), nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after partial frame = %v", err)
	}
}

func TestTCPPartialWriteCancellationCloses(t *testing.T) {
	local, peer := newPipe(t)
	conn := &tcpConn{socket: newSocket(local, 8)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- conn.WritePacket(ctx, []byte{1, 2, 3}) }()

	var part [1]byte
	if _, err := io.ReadFull(peer, part[:]); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitError(t, result, context.Canceled)
	if err := conn.WritePacket(t.Context(), []byte{3}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after partial frame = %v", err)
	}
}

func TestTCPCloseUnblocksReadsAndWrites(t *testing.T) {
	local, _ := newPipe(t)
	observed := &observedConn{Conn: local, reading: make(chan struct{}), writing: make(chan struct{})}
	conn := &tcpConn{socket: newSocket(observed, 8)}
	done := make(chan error, 4)

	read := func() {
		_, err := conn.ReadPacket(t.Context(), make([]byte, 8))
		done <- err
	}
	write := func() { done <- conn.WritePacket(t.Context(), []byte{1}) }
	go read()
	go write()
	for _, started := range []chan struct{}{observed.reading, observed.writing} {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("socket I/O did not start")
		}
	}
	go read()
	go write()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		waitError(t, done, net.ErrClosed)
	}
}
