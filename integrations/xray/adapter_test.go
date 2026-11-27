package xray

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
