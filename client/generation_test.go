package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

type metadataLink struct {
	transport.PacketConn
	negotiated tlscontrol.Negotiation
	done       chan struct{}
}

func (l metadataLink) Info() (tlscontrol.Negotiation, uint8) { return l.negotiated, 0 }
func (l metadataLink) Done() <-chan struct{}                 { return l.done }
func (l metadataLink) Err() error {
	select {
	case <-l.done:
		return net.ErrClosed
	default:
		return nil
	}
}

type observedTunnel struct {
	tunnel.PacketConn
	starts atomic.Int64
}

func (d *observedTunnel) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	d.starts.Add(1)
	return d.PacketConn.ReadPacket(ctx, dst)
}

func (d *observedTunnel) WritePacket(ctx context.Context, data []byte) error {
	d.starts.Add(1)
	return d.PacketConn.WritePacket(ctx, data)
}

func TestRunConfiguredGatesBothGenerationsAndRollsBack(t *testing.T) {
	for _, reject := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			peers := make(chan transport.PacketConn, 2)
			c := retryClient(t, fallbackEndpoints[:2], RetryPolicy{InitialBackoff: time.Millisecond},
				testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
					local, peer := testkit.PacketPipe(1, 64)
					peers <- peer
					return local, nil
				}))
			snapshots := []tunnel.Configuration{
				{IPv4: netip.MustParsePrefix("10.1.0.2/24"), IPv6: netip.MustParsePrefix("fd01::2/64"),
					GatewayIPv4: netip.MustParseAddr("10.1.0.1"), GatewayIPv6: netip.MustParseAddr("fd01::1"), MTU: 1500},
				{IPv4: netip.MustParsePrefix("10.2.0.7/24"), IPv6: netip.MustParsePrefix("fd02::7/64"),
					GatewayIPv4: netip.MustParseAddr("10.2.0.1"), GatewayIPv6: netip.MustParseAddr("fd02::1"), MTU: 1320},
			}
			ended := []chan struct{}{make(chan struct{}), make(chan struct{})}
			for i := range snapshots {
				c.handshakes[i] = func(_ context.Context, _ Endpoint, raw transport.PacketConn) (tunnel.PacketConn, error) {
					return metadataLink{raw, tlscontrol.Negotiation{PeerID: uint32(i + 3), Tunnel: snapshots[i]}, ended[i]}, nil
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if err := c.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			packet, app := testkit.PacketPipe(1, 64)
			defer packet.Close()
			defer app.Close()
			device := &observedTunnel{PacketConn: packet}
			generations := make(chan TunnelGeneration, 2)
			ack := make(chan struct{}, 2)
			rollbacks := make(chan uint64, 2)
			result := make(chan error, 1)
			go func() {
				result <- c.RunConfigured(ctx, device, func(ctx context.Context, info TunnelGeneration) (func(), error) {
					generations <- info
					select {
					case <-ack:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					rollback := func() { rollbacks <- info.Number }
					if reject && info.Number == 2 {
						return rollback, errors.New("private adapter error")
					}
					return rollback, nil
				})
			}()

			for i, expected := range snapshots {
				peer := <-peers
				actual := <-generations
				if actual.Number != uint64(i+1) || actual.Endpoint != fallbackEndpoints[i] ||
					actual.Control.PeerID != uint32(i+3) || actual.Control.Tunnel != expected {
					t.Fatalf("configuration mismatch: %+v", actual)
				}
				before := device.starts.Load()
				if err := peer.WritePacket(ctx, []byte{byte(i + 1)}); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if device.starts.Load() != before || (i == 0 && before != 0) {
					t.Fatal("packet forwarding ran before acknowledgement")
				}
				ack <- struct{}{}
				if reject && i == 1 {
					err := <-result
					assertCode(t, err, CodeTunnel)
					if strings.Contains(err.Error(), "private adapter error") || device.starts.Load() != before {
						t.Fatal("rejected configuration forwarded packets or exposed adapter errors")
					}
					if <-rollbacks != 2 {
						t.Fatal("partial changes were not rolled back")
					}
					peer.Close()
					break
				}
				got := make([]byte, 64)
				n, err := app.ReadPacket(ctx, got)
				if n != 1 || err != nil || got[0] != byte(i+1) {
					t.Fatalf("packet after acknowledgement = %v, %v", got[:n], err)
				}
				if i == 0 {
					// The control session can notify its watchers a little
					// before a forwarding read returns the transport error.
					close(ended[i])
					synctest.Wait()
					select {
					case <-rollbacks:
						t.Fatal("session notification masked the forwarding error")
					default:
					}
					peer.Close()
					if <-rollbacks != 1 {
						t.Fatal("first generation not rolled back")
					}
				} else {
					cancel()
					assertCode(t, <-result, CodeCanceled)
					if <-rollbacks != 2 {
						t.Fatal("last generation not rolled back")
					}
					peer.Close()
				}
			}
			if err := app.WritePacket(t.Context(), []byte{4}); err != nil {
				t.Fatalf("Run closed the borrowed adapter: %v", err)
			}
			c.Close()
		})
	}
}

type mtuTestConn struct {
	transport.PacketConn
	failClose bool
}

func (c mtuTestConn) WritePacket(ctx context.Context, p []byte) error {
	if len(p) == 32 {
		return tunnel.ErrMTUExceeded
	}
	return c.PacketConn.WritePacket(ctx, p)
}

func (c mtuTestConn) Close() error {
	err := c.PacketConn.Close()
	if c.failClose {
		return errors.New("private cleanup detail")
	}
	return err
}

func TestRunConfiguredPacketDropsAndCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		raw, peer := testkit.PacketPipe(2, 256)
		defer peer.Close()
		c := retryClient(t, fallbackEndpoints[:2], RetryPolicy{MaxAttempts: 2},
			testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
				return raw, nil
			}))
		c.config.MaxPacketSize = 64
		c.handshakes[0] = func(_ context.Context, _ Endpoint, raw transport.PacketConn) (tunnel.PacketConn, error) {
			return metadataLink{PacketConn: mtuTestConn{raw, true}, done: make(chan struct{})}, nil
		}
		if err := c.Connect(t.Context()); err != nil {
			t.Fatal(err)
		}
		device, app := testkit.PacketPipe(2, 256)
		defer device.Close()
		defer app.Close()
		results := make(chan error, 1)
		go func() {
			results <- c.RunConfigured(t.Context(), mtuTestConn{PacketConn: device}, func(context.Context, TunnelGeneration) (func(), error) {
				return nil, nil
			})
		}()
		for _, size := range []int{65, 32, 20} {
			if err := app.WritePacket(t.Context(), make([]byte, size)); err != nil {
				t.Fatal(err)
			}
		}
		var got [64]byte
		if n, err := peer.ReadPacket(t.Context(), got[:]); err != nil || n != 20 {
			t.Fatalf("subsequent outbound packet: %d, %v", n, err)
		}
		for _, size := range []int{32, 20} {
			if err := peer.WritePacket(t.Context(), make([]byte, size)); err != nil {
				t.Fatal(err)
			}
		}
		if n, err := app.ReadPacket(t.Context(), got[:]); err != nil || n != 20 {
			t.Fatalf("subsequent inbound packet: %d, %v", n, err)
		}
		synctest.Wait()
		stats := c.Stats()
		if stats.PacketDrops != 3 || stats.Reconnects != 0 || stats.PacketsSent != 1 || stats.PacketsReceived != 1 {
			t.Fatalf("unexpected packet accounting: %+v", stats)
		}
		peer.Close()
		assertCode(t, <-results, CodeCleanup)
		assertCode(t, c.Connect(t.Context()), CodeCleanup)
		reports := c.CompletedGenerationReports(0)
		if len(reports) != 1 || !reports[0].CleanupFailed || reports[0].Code != CodeCleanup {
			t.Fatalf("cleanup report = %+v", reports)
		}
	})
}
