package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

type lookupFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f lookupFunc) LookupNetIP(ctx context.Context, network, name string) ([]netip.Addr, error) {
	return f(ctx, network, name)
}

func TestEndpointResolverAndIdentity(t *testing.T) {
	endpoint := Endpoint{Network: "udp4", Host: "vpn.example.test"}
	resolutions := 0
	var dialed []string
	provided, _ := testkit.PacketPipe(1, 128)
	cfg := Config{Endpoints: []Endpoint{endpoint},
		Resolver: lookupFunc(func(_ context.Context, family, host string) ([]netip.Addr, error) {
			if family != "ip4" || host != endpoint.Host {
				t.Fatalf("lookup %s %s", family, host)
			}
			resolutions++
			addr := "192.0.2.15"
			if resolutions > 1 {
				addr = "192.0.2.16"
			}
			return []netip.Addr{netip.IPv6Loopback(), netip.MustParseAddr("::ffff:192.0.2.14"),
				netip.MustParseAddr("192.0.2.14"), netip.MustParseAddr(addr)}, nil
		}),
		Dialer: testkit.DialerFunc(func(_ context.Context, network, address string) (transport.PacketConn, error) {
			if network != "udp4" {
				t.Fatalf("dial using %s", network)
			}
			dialed = append(dialed, address)
			if len(dialed) == 1 {
				return nil, errors.New("first address unreachable")
			}
			return provided, nil
		}),
	}
	defer provided.Close()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	check := c.config.Endpoints[0]
	var cursor candidateCursor
	for range 2 {
		if _, _, err := c.connectSocket(t.Context(), check, &cursor); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"192.0.2.14:1194", "192.0.2.15:1194", "192.0.2.16:1194"}
	if !slices.Equal(dialed, want) || resolutions != 2 || check.Host != endpoint.Host || check.ServerName != endpoint.Host {
		t.Fatalf("dialed %v, lookups %d, endpoint %+v", dialed, resolutions, check)
	}
}

func TestEndpointLocalBindAndCanceledLookup(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	allocated, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	local := allocated.LocalAddr().(*net.UDPAddr).AddrPort()
	allocated.Close()
	cfg := Config{Endpoints: []Endpoint{{
		Host: "127.0.0.1", Network: "udp4", Port: uint16(listener.LocalAddr().(*net.UDPAddr).Port),
		LocalAddress: local.Addr(), LocalPort: local.Port(),
	}}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	conn, _, err := c.connectSocket(ctx, c.config.Endpoints[0], &candidateCursor{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.WritePacket(ctx, []byte{42}); err != nil {
		t.Fatal(err)
	}
	listener.SetReadDeadline(time.Now().Add(time.Second))
	if _, addr, err := listener.ReadFrom(make([]byte, 10)); err != nil || addr.(*net.UDPAddr).AddrPort() != local {
		t.Fatalf("bound address = %v, %v; want %v", addr, err, local)
	}
	cfg.Endpoints[0] = Endpoint{Host: "vpn.example.test", Network: "tcp6"}
	cfg.Resolver = lookupFunc(func(ctx context.Context, family, name string) ([]netip.Addr, error) {
		if family != "ip6" {
			t.Errorf("lookup family = %s", family)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	other, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	short, stop := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer stop()
	if _, err := other.resolve(short, other.config.Endpoints[0]); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("resolver failure = %v", err)
	}
}

func TestNativeHostnameSocketReportsActualIPv6(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	ep := Endpoint{Host: "localhost", Port: port, Network: "tcp"}
	cfg, err := New(Config{Endpoints: []Endpoint{ep}})
	if err != nil {
		t.Fatal(err)
	}
	conn, network, err := cfg.connectSocket(ctx, ep, &candidateCursor{})
	if err != nil {
		t.Skip("local resolver did not provide the IPv6 loopback address")
	}
	defer conn.Close()
	if network != "tcp6" {
		t.Fatalf("wrong OpenVPN network for connected IPv6 socket: %s", network)
	}
}

func TestTCPHandshakeRetryRotatesResolvedCandidate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		endpoint := Endpoint{Network: "tcp4", Host: "vpn.example.test"}
		var dialed []string
		c, err := New(Config{Endpoints: []Endpoint{endpoint}, Retry: RetryPolicy{MaxAttempts: 2},
			Resolver: lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{
					netip.MustParseAddr("192.0.2.1"),
					netip.MustParseAddr("192.0.2.2"),
					netip.MustParseAddr("192.0.2.3"),
				}, nil
			}),
			Dialer: testkit.DialerFunc(func(_ context.Context, _, addr string) (transport.PacketConn, error) {
				dialed = append(dialed, addr)
				if addr == "192.0.2.1:1194" {
					return nil, errors.New("synthetic socket failure")
				}
				conn, _ := testkit.PacketPipe(1, 64)
				return conn, nil
			}),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.handshakes[0] = func(ctx context.Context, ep Endpoint, conn transport.PacketConn) (tunnel.PacketConn, error) {
			if ep.ServerName != endpoint.Host || ep.Host != endpoint.Host {
				t.Fatal("the retry changed the TLS identity")
			}
			if len(dialed) == 2 {
				return nil, context.DeadlineExceeded
			}
			return acceptTestSession(ctx, ep, conn)
		}
		if err := c.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(dialed, []string{"192.0.2.1:1194", "192.0.2.2:1194", "192.0.2.3:1194"}) {
			t.Fatalf("unexpected retry order: %v", dialed)
		}
	})
}
