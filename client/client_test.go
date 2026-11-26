package client

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

var testEndpoint = Endpoint{Host: "vpn.example", Network: "tcp", Port: 443}

func TestConfigValidationAndCopy(t *testing.T) {
	endpoints := []Endpoint{{Host: "vpn.example."}, {
		Network: "tcp6", Host: "2001:db8::1", Port: 8443, ServerName: "server.example",
	}}
	c, err := New(Config{Endpoints: endpoints})
	if err != nil {
		t.Fatal(err)
	}
	endpoints[0].Host = "changed.example"
	first, second := c.config.Endpoints[0], c.config.Endpoints[1]
	if first.address() != "vpn.example.:1194" || first.Network != "udp" || first.ServerName != "vpn.example" {
		t.Fatalf("first endpoint = %+v", first)
	}
	if second.address() != "[2001:db8::1]:8443" || second.Network != "tcp6" || second.ServerName != "server.example" {
		t.Fatalf("second endpoint = %+v", second)
	}

	for _, cfg := range []Config{
		{},
		{Endpoints: make([]Endpoint, 65)},
		{Endpoints: []Endpoint{{Host: "vpn.example:443"}}},
		{Endpoints: []Endpoint{{Host: "user@vpn.example"}}},
		{Endpoints: []Endpoint{{Host: "vpn.example", ServerName: "*.example"}}},
		{Endpoints: []Endpoint{{Host: "vpn.example", Network: "sctp"}}},
		{Endpoints: []Endpoint{{Host: "::1", Network: "udp4"}}},
		{Endpoints: []Endpoint{testEndpoint}, MaxPacketSize: transport.MaxPacketSize + 1},
		{Endpoints: []Endpoint{testEndpoint}, ConnectTimeout: 3 * time.Minute},
		{Endpoints: []Endpoint{testEndpoint}, HandshakeTimeout: -time.Second},
	} {
		_, err := New(cfg)
		assertCode(t, err, CodeConfig)
		if err != nil && strings.Contains(err.Error(), "user@") {
			t.Fatalf("configuration error leaks input: %v", err)
		}
	}
}

func TestConnectUsesCustomDialerAndClosesUnauthenticatedTransport(t *testing.T) {
	raw, _ := testkit.PacketPipe(0, 64)
	owned := &countedConn{PacketConn: raw}
	c := createTestClient(t, testkit.DialerFunc(func(ctx context.Context, network, address string) (transport.PacketConn, error) {
		if network != "tcp" || address != "vpn.example:443" {
			t.Errorf("dial asked for %q %q", network, address)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Error("dial deadline is missing")
		}
		return owned, nil
	}))
	assertCode(t, c.Connect(t.Context()), CodeUnavailable)
	if c.State() != StateIdle || owned.closes.Load() != 1 {
		t.Fatalf("after failure: state = %s, closes = %d", c.State(), owned.closes.Load())
	}
	if _, ok := c.ActiveEndpoint(); ok {
		t.Fatal("an unauthenticated socket appeared as an active endpoint")
	}
	if err := c.Close(); err != nil || owned.closes.Load() != 1 {
		t.Fatalf("Close = %v, transport closes = %d", err, owned.closes.Load())
	}
}

func TestConnectDialFailureIsRedactedAndReleasesReturnedConn(t *testing.T) {
	raw, _ := testkit.PacketPipe(0, 64)
	owned := &countedConn{PacketConn: raw}
	c := createTestClient(t, testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
		return owned, errors.New("private dialer diagnostic")
	}))
	err := c.Connect(t.Context())
	assertCode(t, err, CodeNetwork)
	if strings.Contains(err.Error(), "private") || errors.Unwrap(err) != nil || owned.closes.Load() != 1 {
		t.Fatalf("error = %v, transport closes = %d", err, owned.closes.Load())
	}
}

func TestConnectionDeadlines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dial := testkit.DialerFunc(func(ctx context.Context, _, _ string) (transport.PacketConn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		cfg := Config{Endpoints: []Endpoint{testEndpoint}, Dialer: dial, ConnectTimeout: 10 * time.Millisecond}
		c, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		c.handshake = acceptTestSession
		before := time.Now()
		err = c.Connect(t.Context())
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(before) != cfg.ConnectTimeout {
			t.Fatalf("dial deadline after %s, error %v", time.Since(before), err)
		}

		raw, _ := testkit.PacketPipe(0, 64)
		owned := &countedConn{PacketConn: raw}
		cfg.Dialer = dialWith(owned)
		cfg.HandshakeTimeout = 25 * time.Millisecond
		c, err = New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		c.handshake = func(ctx context.Context, _ Endpoint, raw transport.PacketConn) (tunnel.PacketConn, error) {
			_, err := raw.ReadPacket(ctx, make([]byte, 32))
			return nil, err
		}
		before = time.Now()
		err = c.Connect(t.Context())
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(before) != cfg.HandshakeTimeout {
			t.Fatalf("handshake deadline after %s, error %v", time.Since(before), err)
		}
		if c.State() != StateIdle || owned.closes.Load() != 1 {
			t.Fatalf("handshake cleanup = %s, %d closes", c.State(), owned.closes.Load())
		}
	})
}

func TestCloseWaitsForCanceledDial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dialing, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		c := createTestClient(t, testkit.DialerFunc(func(ctx context.Context, _, _ string) (transport.PacketConn, error) {
			close(dialing)
			<-ctx.Done()
			close(canceled)
			<-release
			return nil, ctx.Err()
		}))

		connected, closed := make(chan error, 1), make(chan error, 1)
		go func() { connected <- c.Connect(t.Context()) }()
		<-dialing
		if c.State() != StateDialing {
			t.Errorf("state while dialing = %s", c.State())
		}
		assertCode(t, c.Connect(t.Context()), CodeBusy)

		go func() { closed <- c.Close() }()
		<-canceled
		synctest.Wait()
		select {
		case err := <-closed:
			t.Errorf("Close returned before the dialer stopped: %v", err)
		default:
		}
		close(release)
		assertCode(t, <-connected, CodeClosed)
		if err := <-closed; err != nil || c.State() != StateClosed {
			t.Fatalf("Close = %v, state = %s", err, c.State())
		}
		assertCode(t, c.Connect(t.Context()), CodeClosed)
	})
}

func TestCloseDiscardsHandshakeResultAfterCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, _ := testkit.PacketPipe(0, 64)
		owned := &countedConn{PacketConn: raw}
		c := createTestClient(t, dialWith(owned))
		handshaking := make(chan struct{})
		c.handshake = func(ctx context.Context, endpoint Endpoint, _ transport.PacketConn) (tunnel.PacketConn, error) {
			if endpoint.ServerName != "vpn.example" {
				t.Errorf("handshake identity = %q", endpoint.ServerName)
			}
			close(handshaking)
			<-ctx.Done()
			return owned, nil
		}

		connected := make(chan error, 1)
		go func() { connected <- c.Connect(t.Context()) }()
		<-handshaking
		if c.State() != StateHandshaking {
			t.Errorf("state during handshake = %s", c.State())
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		assertCode(t, <-connected, CodeClosed)
		if owned.closes.Load() != 1 || c.State() != StateClosed {
			t.Fatalf("after Close: %d closes, state %s", owned.closes.Load(), c.State())
		}
	})
}

func TestRunForwardsPacketsAndCloseJoinsWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const limit = 64
		ctx := t.Context()
		session, remote := testkit.PacketPipe(1, limit)
		device, app := testkit.PacketPipe(1, limit)
		owned := &countedConn{PacketConn: session}
		c := createTestClient(t, dialWith(owned))
		assertCode(t, c.Run(ctx, device), CodeNotConnected)

		c.handshake = acceptTestSession
		attemptCtx, cancel := context.WithCancel(ctx)
		if err := c.Connect(attemptCtx); err != nil {
			t.Fatal(err)
		}
		cancel()
		if ep, ok := c.ActiveEndpoint(); !ok || ep.ServerName != "vpn.example" {
			t.Fatalf("active endpoint = %+v, %v", ep, ok)
		}

		result := make(chan error, 1)
		go func() { result <- c.Run(ctx, device) }()
		synctest.Wait()
		assertCode(t, c.Run(ctx, device), CodeBusy)

		for _, traffic := range []struct {
			source, sink transport.PacketConn
			packet       []byte
		}{
			{app, remote, []byte{0x45, 1, 2}},
			{remote, app, []byte{0x60, 3, 4}},
		} {
			if err := traffic.source.WritePacket(ctx, traffic.packet); err != nil {
				t.Fatal(err)
			}
			dst := make([]byte, limit)
			n, err := traffic.sink.ReadPacket(ctx, dst)
			if err != nil || !bytes.Equal(dst[:n], traffic.packet) {
				t.Fatalf("forwarded %x, %v; want %x", dst[:n], err, traffic.packet)
			}
		}

		const closers = 4
		results := make(chan error, closers)
		for range closers {
			go func() { results <- c.Close() }()
		}
		for range closers {
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		}
		assertCode(t, <-result, CodeClosed)
		if owned.closes.Load() != 1 {
			t.Fatalf("session closed %d times", owned.closes.Load())
		}
		if err := app.WritePacket(ctx, []byte{1}); err != nil {
			t.Fatalf("caller-owned tunnel was closed: %v", err)
		}
		if _, err := remote.ReadPacket(ctx, nil); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("session still open: %v", err)
		}
	})
}

func TestRunCancellationReleasesSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		session, _ := testkit.PacketPipe(0, 64)
		device, _ := testkit.PacketPipe(0, 64)
		owned := &countedConn{PacketConn: session}
		c := createTestClient(t, dialWith(owned))
		c.handshake = acceptTestSession
		if err := c.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- c.Run(ctx, device) }()
		synctest.Wait()
		cancel()
		err := <-result
		if !errors.Is(err, context.Canceled) || c.State() != StateIdle || owned.closes.Load() != 1 {
			t.Fatalf("Run cleanup error = %v, state = %s, closes = %d", err, c.State(), owned.closes.Load())
		}
	})
}

func createTestClient(t *testing.T, dialer transport.Dialer) *Client {
	t.Helper()
	c, err := New(Config{Endpoints: []Endpoint{testEndpoint}, Dialer: dialer, MaxPacketSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	c.handshake = func(context.Context, Endpoint, transport.PacketConn) (tunnel.PacketConn, error) {
		return nil, &Error{Op: "handshake", Code: CodeUnavailable}
	}
	return c
}

func assertCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != code {
		t.Fatalf("error = %v; want %s", err, code)
	}
}

type countedConn struct {
	transport.PacketConn
	closes atomic.Int32
}

func (c *countedConn) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

func dialWith(conn transport.PacketConn) transport.Dialer {
	return testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
		return conn, nil
	})
}

func acceptTestSession(_ context.Context, _ Endpoint, raw transport.PacketConn) (tunnel.PacketConn, error) {
	return raw, nil
}
