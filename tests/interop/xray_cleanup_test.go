//go:build linux

package interop_test

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/integrations/xray"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

type xrayCleanupPacket struct {
	transport.PacketConn
	closes *atomic.Int32
}

func (p xrayCleanupPacket) Close() error {
	p.closes.Add(1)
	p.PacketConn.Close()
	return errors.New("synthetic transport cleanup error")
}

func TestXrayRunPreservesCoreCleanupResult(t *testing.T) {
	pki := testkit.NewPKI(t)
	f := makePKIFixture(t, interopPeer(t), pki)
	for _, mode := range []string{"cancel", "fixed_mismatch", "concurrent_close"} {
		t.Run(mode, func(t *testing.T) {
			port, _ := startDataPeer(t, f, "udp", "tls", false, "1.3", "AES-256-GCM")
			cfg := f.config(pki, "udp", "tls", port, false)
			var closes atomic.Int32
			cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, network, address string) (transport.PacketConn, error) {
				conn, err := (transport.SocketDialer{}).DialPacket(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return xrayCleanupPacket{conn, &closes}, nil
			})
			device, app := testkit.PacketPipe(1, transport.DefaultPacketSize)
			defer device.Close()
			defer app.Close()
			ready := make(chan struct{})
			var adapter *xray.Adapter
			var err error
			if mode == "fixed_mismatch" {
				adapter, err = xray.New(cfg, device, xray.Addresses{IPv4: netip.MustParseAddr("10.49.0.250")})
			} else {
				adapter, err = xray.NewConfigured(cfg, device, xray.Options{
					Configure: func(context.Context, client.TunnelGeneration) (func(), error) {
						close(ready)
						return nil, nil
					},
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			operation, timeout := context.WithTimeout(t.Context(), 8*time.Second)
			defer timeout()
			ctx, cancel := context.WithCancel(operation)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- adapter.Run(ctx) }()
			if mode != "fixed_mismatch" {
				select {
				case <-ready:
				case <-operation.Done():
					t.Fatal(operation.Err())
				}
				if mode == "concurrent_close" {
					var cleanup *client.Error
					if err := adapter.Close(); !errors.As(err, &cleanup) || cleanup.Code != client.CodeCleanup {
						t.Fatalf("explicit Close: %v", err)
					}
				} else {
					cancel()
				}
			}
			var runErr error
			select {
			case runErr = <-result:
			case <-operation.Done():
				t.Fatal(operation.Err())
			}
			if !errors.Is(runErr, xray.ErrClientCleanup) || closes.Load() != 1 {
				t.Fatalf("lost cleanup or closed twice: %v, closes=%d", runErr, closes.Load())
			}
			var failure *client.Error
			switch mode {
			case "fixed_mismatch":
				if !errors.Is(runErr, xray.ErrTunnelAddress) {
					t.Fatalf("lost fixed-address failure: %v", runErr)
				}
			case "cancel":
				if !errors.Is(runErr, context.Canceled) || !errors.As(runErr, &failure) || failure.Code != client.CodeCanceled {
					t.Fatalf("lost primary cancellation: %v", runErr)
				}
			case "concurrent_close":
				if !errors.As(runErr, &failure) || failure.Code != client.CodeClosed {
					t.Fatalf("lost primary closed status: %v", runErr)
				}
			}
		})
	}
}
