package xray

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

func TestFixedAddressesRequireAnExactAssignment(t *testing.T) {
	expected := Addresses{IPv4: netip.MustParseAddr("10.49.0.2")}
	current := client.ControlInfo{TunnelIP: expected.IPv4}
	if !expected.matches(current) {
		t.Fatal("expected the fixed assignment to match")
	}
	current.TunnelIP = netip.MustParseAddr("10.49.0.3")
	if expected.matches(current) {
		t.Fatal("changed IPv4 assignment matched")
	}
}

func TestCanceledAdapterClosesClientAndBorrowsDevice(t *testing.T) {
	device := &countingDevice{}
	adapter, err := New(client.Config{Endpoints: []client.Endpoint{{Host: "vpn.example.test"}}},
		device, Addresses{IPv4: netip.MustParseAddr("10.49.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := adapter.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled run: %v", err)
	}
	if adapter.Stats().State != client.StateClosed || device.closed {
		t.Fatal("adapter did not close the owned client or closed the borrowed device")
	}
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
}

type countingDevice struct {
	calls  int
	closed bool
}

func (d *countingDevice) ReadPacket(context.Context, []byte) (int, error) {
	d.calls++
	return 0, nil
}

func (d *countingDevice) WritePacket(context.Context, []byte) error {
	d.calls++
	return nil
}

func (d *countingDevice) Close() error {
	d.closed = true
	return nil
}

func TestFixedIPv6MSSPreflight(t *testing.T) {
	config := client.Config{Endpoints: []client.Endpoint{{Host: "vpn.example.test"}}}
	device := &countingDevice{}
	for _, ipv4 := range []netip.Addr{{}, netip.MustParseAddr("10.0.0.2")} {
		addresses := Addresses{IPv4: ipv4, IPv6: netip.MustParsePrefix("fd00::2/64")}
		if adapter, err := NewFixed(config, device, addresses, Options{MSSMTU: 1279}); adapter != nil || !errors.Is(err, ErrTunnelConfig) {
			t.Fatalf("subminimum IPv6 MTU was accepted: %v", err)
		}
		for _, mtu := range []int{0, 1280} {
			adapter, err := NewFixed(config, device, addresses, Options{MSSMTU: mtu})
			if err != nil {
				t.Fatal(err)
			}
			adapter.Close()
		}
	}
	if device.calls != 0 || device.closed {
		t.Fatal("validation touched the borrowed device")
	}
}

func TestDialDNSPreservesAuthorizedCallerCancellation(t *testing.T) {
	server := netip.MustParseAddrPort("192.0.2.1:53")
	scopeCtx, retire := context.WithCancel(t.Context())
	defer retire()
	scope := &dnsScope{
		ctx: scopeCtx, generation: 1,
		config:      tunnel.DNSConfig{Servers: []tunnel.DNSServer{{Addresses: []netip.AddrPort{server}}}},
		connections: make(map[*dnsConn]struct{}),
	}
	entered := make(chan struct{})
	calls := 0
	a := &Adapter{options: Options{DNSDialer: func(ctx context.Context, _ string, _ netip.AddrPort) (net.Conn, error) {
		calls++
		close(entered)
		<-ctx.Done()
		return nil, errors.New("private callback error")
	}}}
	a.dns.Store(scope)
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := a.DialDNS(expired, 1, "udp", server); !errors.Is(err, context.DeadlineExceeded) || calls != 0 {
		t.Fatalf("expired dial = %v, calls=%d", err, calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := a.DialDNS(ctx, 1, "tcp", server)
		done <- err
	}()
	<-entered
	cancel()
	retire()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authorized dial = %v", err)
	}
	if _, err := a.DialDNS(ctx, 1, "udp", server); !errors.Is(err, ErrDNSUnavailable) {
		t.Fatalf("retired scope = %v", err)
	}
	scope.close()
}

type failingDNSClose struct {
	net.Conn
	err   error
	count *atomic.Int32
}

func (c failingDNSClose) Close() error {
	c.count.Add(1)
	c.Conn.Close()
	return c.err
}

func TestDNSCleanupReportedBeforeRollback(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		fail bool
	}{
		{"uncertain", errors.New("private DNS close error"), true},
		{"already_closed", net.ErrClosed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			server := netip.MustParseAddrPort("192.0.2.1:53")
			gen := client.TunnelGeneration{Number: 1}
			gen.Control.Tunnel = gen.Control.Tunnel.WithNetworkOptions(nil,
				tunnel.DNSConfig{Servers: []tunnel.DNSServer{{Addresses: []netip.AddrPort{server}}}})
			socket, peer := net.Pipe()
			defer peer.Close()
			var closes atomic.Int32
			var rollbacks, setups int
			a := new(Adapter)
			a.options = Options{
				DNSDialer: func(context.Context, string, netip.AddrPort) (net.Conn, error) {
					return failingDNSClose{socket, tc.err, &closes}, nil
				},
				Configure: func(context.Context, client.TunnelGeneration) (func(), error) {
					setups++
					return func() {
						rollbacks++
						if closes.Load() != 1 || a.dnsCleanupFailed != tc.fail {
							t.Error("rollback started before the DNS socket result was recorded")
						}
					}, nil
				},
			}
			rollback, err := a.prepare(ctx, gen)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := a.DialDNS(ctx, gen.Number, "udp", server)
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			rollback()
			if err := conn.Close(); errors.Is(err, ErrDNSCleanup) != tc.fail || closes.Load() != 1 || rollbacks != 1 ||
				(tc.fail && strings.Contains(err.Error(), "private")) {
				t.Fatalf("redacted registered socket result: %v", err)
			}
			if _, err := a.DialDNS(t.Context(), gen.Number, "udp", server); !errors.Is(err, ErrDNSUnavailable) {
				t.Fatal("retired DNS generation remained callable")
			}
			if tc.fail {
				gen.Number++
				if _, err := a.prepare(t.Context(), gen); !errors.Is(err, ErrDNSCleanup) || setups != 1 {
					t.Fatalf("uncertain scope allowed host reconfiguration: %v", err)
				}
			}
		})
	}
}

func TestDNSRetirementJoinsPartialSocketFailure(t *testing.T) {
	server := netip.MustParseAddrPort("192.0.2.1:53")
	scopeCtx, retire := context.WithCancel(t.Context())
	defer retire()
	scope := &dnsScope{ctx: scopeCtx, generation: 1,
		config: tunnel.DNSConfig{Servers: []tunnel.DNSServer{{Addresses: []netip.AddrPort{server}}}}}
	raw, peer := net.Pipe()
	defer peer.Close()
	var closes atomic.Int32
	entered, finishing := make(chan struct{}), make(chan struct{})
	a := &Adapter{options: Options{DNSDialer: func(ctx context.Context, _ string, _ netip.AddrPort) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		<-finishing
		return failingDNSClose{raw, errors.New("private close failure"), &closes}, errors.New("private dial failure")
	}}}
	a.dns.Store(scope)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	dial := make(chan error, 1)
	go func() {
		_, err := a.DialDNS(ctx, 1, "udp", server)
		dial <- err
	}()
	<-entered
	retire()
	cancel()
	result := make(chan bool, 1)
	go func() { result <- scope.close() }()
	if _, err := a.DialDNS(t.Context(), 1, "udp", server); !errors.Is(err, ErrDNSUnavailable) {
		t.Fatalf("retired scope accepted another dial: %v", err)
	}
	select {
	case <-result:
		t.Fatal("scope returned before pending DNS cleanup")
	default:
	}
	close(finishing)
	if err := <-dial; !errors.Is(err, context.Canceled) || !errors.Is(err, ErrDNSCleanup) ||
		strings.Contains(err.Error(), "private") {
		t.Fatalf("lost canceled dial or cleanup result: %v", err)
	}
	if !<-result || closes.Load() != 1 {
		t.Fatal("partial socket outcome or ownership lost during retirement")
	}
}
