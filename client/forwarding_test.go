package client

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

type failingForwardConn struct {
	tunnel.PacketConn
	read  func(context.Context) (int, error)
	write func(context.Context) error
}

func (c failingForwardConn) ReadPacket(ctx context.Context, b []byte) (int, error) {
	if c.read != nil {
		return c.read(ctx)
	}
	return c.PacketConn.ReadPacket(ctx, b)
}

func (c failingForwardConn) WritePacket(ctx context.Context, b []byte) error {
	if c.write != nil {
		return c.write(ctx)
	}
	return c.PacketConn.WritePacket(ctx, b)
}

func TestRunConfiguredStopsOnIndependentDeviceFailure(t *testing.T) {
	for _, sessionFirst := range []bool{true, false} {
		dials := 0
		deviceErr := errors.New("private device detail")
		sessionRead := func(ctx context.Context) (int, error) {
			if !sessionFirst {
				<-ctx.Done()
			}
			return 0, io.EOF
		}
		deviceRead := func(ctx context.Context) (int, error) {
			if sessionFirst {
				<-ctx.Done()
			}
			return 0, deviceErr
		}
		c := retryClient(t, fallbackEndpoints[:2], RetryPolicy{InitialBackoff: time.Millisecond},
			testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
				dials++
				local, peer := testkit.PacketPipe(1, 64)
				t.Cleanup(func() { peer.Close() })
				return local, nil
			}))
		for i := range c.handshakes {
			c.handshakes[i] = func(_ context.Context, _ Endpoint, raw transport.PacketConn) (tunnel.PacketConn, error) {
				if dials > 1 {
					return nil, tlscontrol.ErrAuth
				}
				return failingForwardConn{PacketConn: raw, read: sessionRead}, nil
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		if err := c.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		err := c.RunConfigured(ctx, failingForwardConn{read: deviceRead}, nil)
		if errorCode(err) != CodeTunnel || dials != 1 || err.Error() == deviceErr.Error() {
			t.Fatalf("session first %v: RunConfigured = %v, dials = %d", sessionFirst, err, dials)
		}
		c.Close()
	}
}

func TestForwardingIndependentWriteAndCancellation(t *testing.T) {
	readOne := func(context.Context) (int, error) { return 1, nil }
	for _, tc := range []struct {
		name          string
		write, second error
		want          ErrorCode
	}{
		{"device write", errors.New("dead device"), io.EOF, CodeTunnel},
		{"peer halt", errors.New("dead device"), tlscontrol.ErrPeerStopped, CodePeerStopped},
		{"peer auth", errors.New("dead device"), tlscontrol.ErrAuth, CodeAuthentication},
		{"cancelled device", net.ErrClosed, io.EOF, CodeNetwork},
		{"cancelled deadline", context.DeadlineExceeded, io.EOF, CodeNetwork},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			writing := make(chan struct{})
			device := failingForwardConn{
				read: func(ctx context.Context) (int, error) {
					<-writing
					return readOne(ctx)
				},
				write: func(ctx context.Context) error {
					close(writing)
					<-ctx.Done()
					return tc.write
				},
			}
			// The outgoing worker can report a session error from a write,
			// while the incoming worker is stuck in a device write.
			session := failingForwardConn{read: readOne, write: func(context.Context) error { return tc.second }}
			c := &Client{}
			got := c.forwardSession(ctx, device, &connection{link: session}, make([]byte, 64), make([]byte, 64))
			if got.err.Code != tc.want {
				t.Fatalf("forwarding = %v, want %v", got.err, tc.want)
			}
		})
	}
}
