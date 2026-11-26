package client

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

var fallbackEndpoints = []Endpoint{
	{Host: "first.example.test", Port: 981, Network: "udp4", ServerName: "first-identity.example.test"},
	{Host: "second.example.test", Port: 982, Network: "tcp4", ServerName: "second-identity.example.test"},
	{Host: "third.example.test", Port: 983, Network: "tcp6", ServerName: "third-identity.example.test"},
}

func retryClient(t *testing.T, endpoints []Endpoint, policy RetryPolicy, dial transport.Dialer) *Client {
	t.Helper()
	c, err := New(Config{Endpoints: endpoints, Retry: policy, Dialer: dial})
	if err != nil {
		t.Fatal(err)
	}
	for i := range c.handshakes {
		c.handshakes[i] = acceptTestSession
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRetryConfigurationLimits(t *testing.T) {
	for _, p := range []RetryPolicy{
		{MaxAttempts: -2},
		{MaxAttempts: 1025},
		{InitialBackoff: time.Microsecond},
		{MaxBackoff: 6 * time.Minute},
		{InitialBackoff: time.Second, MaxBackoff: time.Millisecond},
	} {
		_, err := New(Config{Endpoints: fallbackEndpoints, Retry: p})
		assertCode(t, err, CodeConfig)
	}
}

func TestRetryBudgetAndTerminalClassification(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		code  ErrorCode
	}{
		{"certificate", tlscontrol.ErrCertificate, CodeCertificate},
		{"authentication", tlscontrol.ErrAuth, CodeAuthentication},
		{"negotiation", tlscontrol.ErrNegotiation, CodeProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var dials []string
				c := retryClient(t, fallbackEndpoints, RetryPolicy{MaxAttempts: UnlimitedAttempts},
					testkit.DialerFunc(func(_ context.Context, network, address string) (transport.PacketConn, error) {
						dials = append(dials, network+" "+address)
						if len(dials) == 1 {
							return nil, errors.New("private-network-detail")
						}
						packets, _ := testkit.PacketPipe(0, 64)
						return packets, nil
					}))
				c.handshakes[1] = func(context.Context, Endpoint, transport.PacketConn) (tunnel.PacketConn, error) {
					return nil, setControlError(tc.cause)
				}
				assertCode(t, c.Connect(t.Context()), tc.code)
				want := []string{"udp4 first.example.test:981", "tcp4 second.example.test:982"}
				if !slices.Equal(dials, want) || c.State() != StateIdle {
					t.Fatalf("terminal failure dialed %v", dials)
				}
				stats := c.Stats()
				if stats.Attempts != 2 || stats.AttemptFailures != 2 || stats.ActiveEndpointIndex != -1 || stats.LastError != tc.code {
					t.Fatalf("unexpected stats: %+v", stats)
				}
			})
		})
	}
	synctest.Test(t, func(t *testing.T) {
		var dials []string
		var at []time.Time
		c := retryClient(t, fallbackEndpoints[:2], RetryPolicy{
			MaxAttempts: 4, InitialBackoff: 100 * time.Millisecond, MaxBackoff: 225 * time.Millisecond,
		}, testkit.DialerFunc(func(_ context.Context, _, address string) (transport.PacketConn, error) {
			dials = append(dials, address)
			at = append(at, time.Now())
			return nil, errors.New("synthetic connect failure")
		}))
		assertCode(t, c.Connect(t.Context()), CodeNetwork)
		want := []string{fallbackEndpoints[0].address(), fallbackEndpoints[1].address(), fallbackEndpoints[0].address(), fallbackEndpoints[1].address()}
		if !slices.Equal(dials, want) {
			t.Fatalf("attempt order = %v", dials)
		}
		for i, ceiling := range []time.Duration{100, 200, 225} {
			ceiling *= time.Millisecond
			if d := at[i+1].Sub(at[i]); d < ceiling/2 || d > ceiling {
				t.Fatalf("delay %d = %v, ceiling %v", i, d, ceiling)
			}
		}
	})
}

func TestCancelOrCloseDuringRetry(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			dials := 0
			c := retryClient(t, fallbackEndpoints, RetryPolicy{
				MaxAttempts: UnlimitedAttempts, InitialBackoff: time.Minute,
			}, testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
				dials++
				return nil, errors.New("unreachable")
			}))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- c.Connect(ctx) }()
			synctest.Wait()
			if c.State() != StateBackoff {
				t.Fatalf("state = %s", c.State())
			}
			start := time.Now()
			if closeClient {
				closed := make(chan error, 2)
				for range 2 {
					go func() { closed <- c.Close() }()
				}
				for range 2 {
					if err := <-closed; err != nil {
						t.Fatal(err)
					}
				}
				assertCode(t, <-done, CodeClosed)
			} else {
				cancel()
				assertCode(t, <-done, CodeCanceled)
			}
			if time.Since(start) != 0 || dials != 1 {
				t.Fatalf("retry cancellation took %v, dials %d", time.Since(start), dials)
			}
		})
	}
}

func TestRunReconnectsAndResetsBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const generations = 25
		var dials []string
		var connections []*countedConn
		peers := make(chan transport.PacketConn, 3)
		c := retryClient(t, fallbackEndpoints[:2], RetryPolicy{InitialBackoff: 100 * time.Millisecond},
			testkit.DialerFunc(func(_ context.Context, _, address string) (transport.PacketConn, error) {
				dials = append(dials, address)
				if len(dials)%2 == 0 {
					return nil, errors.New("temporary network loss")
				}
				local, peer := testkit.PacketPipe(1, 64)
				counted := &countedConn{PacketConn: local}
				connections = append(connections, counted)
				peers <- peer
				return counted, nil
			}))
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		if err := c.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		device, app := testkit.PacketPipe(1, 64)
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx, device) }()
		for generation := range generations {
			peer := <-peers
			synctest.Wait()
			if ep, ok := c.ActiveEndpoint(); !ok || ep != fallbackEndpoints[0] {
				t.Fatalf("active endpoint in generation %d = %+v, %v", generation, ep, ok)
			}
			if err := app.WritePacket(ctx, []byte{1, 2, 3}); err != nil {
				t.Fatal(err)
			}
			if n, err := peer.ReadPacket(ctx, make([]byte, 8)); n != 3 || err != nil {
				t.Fatalf("outbound after recovery = %d, %v", n, err)
			}
			if err := peer.WritePacket(ctx, []byte{4, 5}); err != nil {
				t.Fatal(err)
			}
			if n, err := app.ReadPacket(ctx, make([]byte, 8)); n != 2 || err != nil {
				t.Fatalf("inbound after recovery = %d, %v", n, err)
			}
			if generation < generations-1 {
				peer.Close()
			}
		}
		synctest.Wait()
		snapshot := c.Stats()
		if snapshot.Attempts != 2*generations-1 || snapshot.Connections != generations ||
			snapshot.Reconnects != generations-1 || snapshot.Disconnects != generations-1 ||
			snapshot.ActiveEndpointIndex != 0 || snapshot.PacketsSent != generations || snapshot.BytesSent != 3*generations ||
			snapshot.PacketsReceived != generations || snapshot.BytesReceived != 2*generations {
			t.Fatalf("unexpected reconnect stats: %+v", snapshot)
		}
		for i, address := range dials {
			if address != fallbackEndpoints[i%2].address() {
				t.Fatalf("reconnect dialed %v", dials)
			}
		}
		cancel()
		assertCode(t, <-done, CodeCanceled)
		for _, packets := range connections {
			if packets.closes.Load() != 1 {
				t.Fatal("session was not closed exactly once")
			}
		}
		if err := app.WritePacket(t.Context(), []byte{6}); err != nil {
			t.Fatalf("borrowed tunnel was closed: %v", err)
		}
	})
}

func TestCloseJoinsRunDuringReconnectBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, peer := testkit.PacketPipe(0, 64)
		owned := &countedConn{PacketConn: raw}
		var dials int
		c := retryClient(t, fallbackEndpoints, RetryPolicy{MaxAttempts: UnlimitedAttempts, InitialBackoff: time.Minute},
			testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
				dials++
				return owned, nil
			}))
		if err := c.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		device, _ := testkit.PacketPipe(0, 64)
		done := make(chan error, 1)
		go func() { done <- c.Run(t.Context(), device) }()
		synctest.Wait()
		peer.Close()
		synctest.Wait()
		if c.State() != StateBackoff || c.Stats().ActiveEndpointIndex != -1 {
			t.Fatalf("disconnected state = %s", c.State())
		}
		assertCode(t, c.Connect(t.Context()), CodeBusy)
		assertCode(t, c.Run(t.Context(), device), CodeBusy)
		start := time.Now()
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if time.Since(start) != 0 || dials != 1 || owned.closes.Load() != 1 || c.State() != StateClosed {
			t.Fatal("Close did not stop and join the recovery operation")
		}
		assertCode(t, <-done, CodeClosed)
	})
}

func TestRunStopsOnTerminalSessionOrTunnelErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cause   error
		device  bool
		disable bool
		code    ErrorCode
	}{
		{"security", tlscontrol.ErrAuth, false, false, CodeAuthentication},
		{"halt", tlscontrol.ErrPeerStopped, false, false, CodePeerStopped},
		{"tunnel", errors.New("private-packet-metadata"), true, false, CodeTunnel},
		{"disabled", net.ErrClosed, false, true, CodeNetwork},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, peer := testkit.PacketPipe(0, 64)
			defer peer.Close()
			device, app := testkit.PacketPipe(0, 64)
			defer app.Close()
			var dials int
			c := retryClient(t, fallbackEndpoints, RetryPolicy{DisableReconnect: tc.disable},
				testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
					dials++
					return raw, nil
				}))
			c.handshakes[0] = func(context.Context, Endpoint, transport.PacketConn) (tunnel.PacketConn, error) {
				if tc.device {
					return raw, nil
				}
				return &failedReader{PacketConn: raw, cause: tc.cause}, nil
			}
			if err := c.Connect(t.Context()); err != nil {
				t.Fatal(err)
			}
			if tc.device {
				device = &failedReader{PacketConn: device, cause: tc.cause}
			}
			err := c.Run(t.Context(), device)
			assertCode(t, err, tc.code)
			if dials != 1 || strings.Contains(err.Error(), "private") {
				t.Fatal("terminal forwarding failure retried or leaked details")
			}
		})
	}
}

func TestSessionShutdownCausePreventsFallback(t *testing.T) {
	raw, _ := testkit.PacketPipe(0, 64)
	link := &terminalSession{
		failedReader: &failedReader{PacketConn: raw, cause: net.ErrClosed},
		done:         make(chan struct{}),
	}
	dials := 0
	c := retryClient(t, fallbackEndpoints, RetryPolicy{MaxAttempts: UnlimitedAttempts},
		testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
			dials++
			return raw, nil
		}))
	c.handshakes[0] = func(context.Context, Endpoint, transport.PacketConn) (tunnel.PacketConn, error) {
		return link, nil
	}
	if err := c.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	device, _ := testkit.PacketPipe(0, 64)
	assertCode(t, c.Run(t.Context(), device), CodeAuthentication)
	if dials != 1 || c.Stats().LastError != CodeAuthentication {
		t.Fatal("transport closure masked a terminal session failure")
	}
}

type failedReader struct {
	transport.PacketConn
	cause error
}

func (f *failedReader) ReadPacket(context.Context, []byte) (int, error) {
	return 0, f.cause
}

type terminalSession struct {
	*failedReader
	done chan struct{}
}

func (s *terminalSession) Done() <-chan struct{} { return s.done }
func (s *terminalSession) Err() error            { return tlscontrol.ErrAuth }
func (s *terminalSession) Close() error {
	close(s.done)
	return s.PacketConn.Close()
}

func TestEventHistoryIsBoundedAndRedacted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const secret = "sensitive-observability-marker"
		endpoints := []Endpoint{{Host: secret + ".example.test"}}
		c := retryClient(t, endpoints, RetryPolicy{MaxAttempts: 100, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond},
			testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
				return nil, errors.New(secret)
			}))
		assertCode(t, c.Connect(t.Context()), CodeNetwork)
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		events := c.Events(0)
		if len(events) != 64 || events[0].Sequence == 1 || events[63].Kind != EventClosed ||
			len(c.Events(events[62].Sequence)) != 1 || len(c.Events(events[63].Sequence)) != 0 {
			t.Fatal("incorrect bounded event history")
		}
		for i, event := range events {
			if event.Sequence != events[0].Sequence+uint64(i) || event.EndpointIndex < -1 || event.EndpointIndex >= 1 {
				t.Fatalf("invalid event: %+v", event)
			}
		}
		b, err := json.Marshal(struct {
			Events []Event
			Stats  Stats
		}{events, c.Stats()})
		if err != nil || strings.Contains(string(b), secret) {
			t.Fatal("observability exposed private values")
		}
		events[63].Kind = "modified"
		if c.Events(events[62].Sequence)[0].Kind != EventClosed {
			t.Fatal("event caller could mutate history")
		}
	})
}
