package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
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

func TestResolveFailureClassification(t *testing.T) {
	wait := lookupFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	for _, tc := range []struct {
		name   string
		budget time.Duration
		lookup lookupFunc
		parent bool
		code   ErrorCode
	}{
		{"resolver_timeout", 0, func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, &net.DNSError{IsTimeout: true, Name: "private.test", Err: "private timeout"}
		}, false, CodeTimeout},
		{"resolver_budget", 10 * time.Millisecond, wait, false, CodeTimeout},
		{"dial_deadline", 0, wait, false, CodeTimeout},
		{"parent_cancel", 100 * time.Millisecond, wait, true, CodeCanceled},
		{"name_not_found", 0, func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, &net.DNSError{IsNotFound: true, Name: "private.test", Err: "private name"}
		}, false, CodeNetwork},
		{"filtered_addresses", 0, func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.IPv6Loopback(), netip.IPv4Unspecified()}, nil
		}, false, CodeNetwork},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := retryClient(t, fallbackEndpoints[:1], RetryPolicy{MaxAttempts: 1},
					testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
						t.Error("unexpected dial after failed DNS resolution")
						return nil, net.ErrClosed
					}))
				c.config.Resolver, c.config.ResolveRetry = tc.lookup, tc.budget
				c.config.ConnectTimeout = 200 * time.Millisecond
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if tc.parent {
					go func() {
						time.Sleep(time.Millisecond)
						cancel()
					}()
				}
				err := c.Connect(ctx)
				assertCode(t, err, tc.code)
				if strings.Contains(err.Error(), "private") || errors.Is(err, context.DeadlineExceeded) != (tc.code == CodeTimeout) ||
					errors.Is(err, context.Canceled) != (tc.code == CodeCanceled) {
					t.Fatalf("unexpected public resolution error: %v", err)
				}
				reports := c.AttemptReports(0)
				if len(reports) != 1 || reports[0].Stage != StageResolve || reports[0].Code != tc.code {
					t.Fatalf("unexpected resolve report: %+v", reports)
				}
				if tc.code != CodeCanceled && c.Stats().LastError != tc.code {
					t.Fatalf("unexpected last error: %+v", c.Stats())
				}
			})
		})
	}
}

func TestResolveRetriesTransientTimeoutWithinBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var lookups, dials int
		c := retryClient(t, fallbackEndpoints[:1], RetryPolicy{MaxAttempts: 1},
			testkit.DialerFunc(func(_ context.Context, _, address string) (transport.PacketConn, error) {
				dials++
				if address != "192.0.2.1:981" {
					t.Fatalf("unexpected resolved address: %s", address)
				}
				local, peer := testkit.PacketPipe(1, 64)
				t.Cleanup(func() { peer.Close() })
				return local, nil
			}))
		c.config.ResolveRetry = 2 * time.Second
		c.config.Resolver = lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			lookups++
			if lookups == 1 {
				return nil, &net.DNSError{IsTimeout: true}
			}
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		})
		if err := c.Connect(t.Context()); err != nil || lookups != 2 || dials != 1 {
			t.Fatalf("DNS retry did not recover: %v, lookups=%d dials=%d", err, lookups, dials)
		}
	})
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

func TestRemoteRejectsLimitedBroadcast(t *testing.T) {
	dials := 0
	dialer := testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
		dials++
		return nil, net.ErrClosed
	})
	for _, host := range []string{"255.255.255.255", "::ffff:255.255.255.255"} {
		ep := Endpoint{Host: host}
		_, err := ep.Validated()
		assertCode(t, err, CodeConfig)
		_, err = New(Config{Endpoints: []Endpoint{ep}, Dialer: dialer})
		assertCode(t, err, CodeConfig)
	}
	c := retryClient(t, []Endpoint{{Host: "vpn.example.test", Network: "udp4"}}, RetryPolicy{MaxAttempts: 1}, dialer)
	c.config.Resolver = lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("255.255.255.255"), netip.MustParseAddr("::ffff:255.255.255.255")}, nil
	})
	assertCode(t, c.Connect(t.Context()), CodeNetwork)
	if dials != 0 {
		t.Fatal("limited broadcast reached the dialer")
	}
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "169.254.4.3", "::ffff:192.0.2.1", "fe80::1%fixture"} {
		if _, err := (Endpoint{Host: host}).Validated(); err != nil {
			t.Fatalf("unicast %s = %v", host, err)
		}
	}
	if _, err := (Endpoint{Host: "192.0.2.1", LocalAddress: netip.IPv4Unspecified()}).Validated(); err != nil {
		t.Fatalf("local wildcard = %v", err)
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
