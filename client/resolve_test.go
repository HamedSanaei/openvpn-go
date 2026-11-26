package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
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
	for visit := range 2 {
		if _, _, err := c.connectSocket(t.Context(), check, visit); err != nil {
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
	conn, _, err := c.connectSocket(ctx, c.config.Endpoints[0], 0)
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
