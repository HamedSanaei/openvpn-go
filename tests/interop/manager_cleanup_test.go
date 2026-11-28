//go:build linux

package interop_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/integrations/sessions"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

type leaseCleanupFailure struct {
	transport.PacketConn
	count *atomic.Int32
}

func (p leaseCleanupFailure) Close() error {
	p.count.Add(1)
	p.PacketConn.Close()
	return errors.New("synthetic close failure")
}

func TestManagedLeasePreservesCleanupResult(t *testing.T) {
	pki := testkit.NewPKI(t)
	f := makePKIFixture(t, interopPeer(t), pki)
	for _, reject := range []bool{false, true} {
		name := "cancel_after_forwarding"
		if reject {
			name = "terminal_authentication"
		}
		t.Run(name, func(t *testing.T) {
			port, echo := startDataPeer(t, f, "udp", "tls", reject, "1.3", "AES-256-GCM")
			cfg := f.config(pki, "udp", "tls", port, reject)
			wantCode, wantClientFailure := client.CodeCanceled, true
			var deviceCloses, transportCloses atomic.Int32
			if reject {
				cfg.Credentials.Password = "invalid-test-password"
				wantCode, wantClientFailure = client.CodeAuthentication, false
			} else {
				cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, network, address string) (transport.PacketConn, error) {
					link, err := (transport.SocketDialer{}).DialPacket(ctx, network, address)
					if err != nil {
						return nil, err
					}
					return leaseCleanupFailure{link, &transportCloses}, nil
				})
			}
			manager, err := sessions.New(sessions.Limits{Sessions: 1, PacketBytes: transport.DefaultPacketSize})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			device, app := testkit.PacketPipe(8, transport.DefaultPacketSize)
			defer app.Close()
			ready := make(chan client.ControlInfo, 1)
			lease, err := manager.Start(ctx, "owned", cfg, func(context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error) {
				return leaseCleanupFailure{device, &deviceCloses}, func(_ context.Context, g client.TunnelGeneration) (func(), error) {
					ready <- g.Control
					return nil, nil
				}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !reject {
				select {
				case info := <-ready:
					roundtrip(t, app, echo, info.TunnelIP.AsSlice(), []byte("managed lease before cancellation"))
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				lease.Stop()
			}
			status, err := lease.Wait(ctx)
			if err != nil || status.Code != wantCode || !status.Cleanup.DeviceFailed ||
				status.Cleanup.ClientFailed != wantClientFailure || deviceCloses.Load() != 1 ||
				(transportCloses.Load() == 1) != wantClientFailure || manager.Usage() != (sessions.Usage{}) {
				t.Fatalf("unexpected owned cleanup: %+v, %v", status, err)
			}
		})
	}
}
