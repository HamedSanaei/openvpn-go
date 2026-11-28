package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type deadlineFaultConn struct {
	net.Conn
	entered chan struct{}
	closes  atomic.Int32
}

func (c *deadlineFaultConn) Read(p []byte) (int, error) {
	close(c.entered)
	return c.Conn.Read(p)
}

func (c *deadlineFaultConn) Write(p []byte) (int, error) {
	close(c.entered)
	return c.Conn.Write(p)
}

func (c *deadlineFaultConn) SetReadDeadline(when time.Time) error {
	if !when.IsZero() {
		return errors.New("deadline unavailable")
	}
	return c.Conn.SetReadDeadline(when)
}

func (c *deadlineFaultConn) SetWriteDeadline(when time.Time) error {
	if !when.IsZero() {
		return errors.New("deadline unavailable")
	}
	return c.Conn.SetWriteDeadline(when)
}

func (c *deadlineFaultConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func TestDeadlineFallbackPreservesInitiatingContext(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, op := range []string{"read", "write"} {
			for _, trigger := range []string{"cancel", "deadline", "peer-close"} {
				t.Run(network+"/"+op+"/"+trigger, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						raw, peer := net.Pipe()
						defer peer.Close()
						wire := &deadlineFaultConn{Conn: raw, entered: make(chan struct{})}
						s := newSocket(wire, 64)
						var conn PacketConn = &tcpConn{socket: s}
						if network == "udp" {
							conn = &udpConn{socket: s}
						}
						defer conn.Close()
						ctx, cancel := context.WithCancel(t.Context())
						defer cancel()
						var want error = context.Canceled
						if trigger == "deadline" {
							var stop context.CancelFunc
							ctx, stop = context.WithTimeout(ctx, time.Second)
							defer stop()
							want = context.DeadlineExceeded
						}
						result := make(chan error, 1)
						go func() {
							if op == "write" {
								result <- conn.WritePacket(ctx, []byte{42})
							} else {
								_, err := conn.ReadPacket(ctx, make([]byte, 64))
								result <- err
							}
						}()
						<-wire.entered
						switch trigger {
						case "cancel":
							cancel()
						case "peer-close":
							peer.Close()
							want = io.EOF
							if op == "write" {
								want = io.ErrClosedPipe
							}
						}
						if err := <-result; !errors.Is(err, want) {
							t.Fatalf("operation lost its initiating cause: %v", err)
						}
						if trigger != "peer-close" {
							if err := conn.WritePacket(t.Context(), []byte{1}); !errors.Is(err, net.ErrClosed) || wire.closes.Load() != 1 {
								t.Fatalf("forced socket closure was reusable: %v", err)
							}
						}
					})
				})
			}
		}
	}
}
