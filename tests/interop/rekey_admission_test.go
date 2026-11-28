//go:build linux

package interop_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
	"github.com/hamedsanaei/openvpn-go/transport"
)

type admissionObserver struct {
	rekeyObserver
	writes atomic.Uint32
}

func (o *admissionObserver) WritePacket(ctx context.Context, packet []byte) error {
	if len(packet) != 0 && wire.Opcode(packet[0]>>3) == wire.SoftReset {
		o.writes.Add(1)
	}
	return o.rekeyObserver.WritePacket(ctx, packet)
}

func TestRekeyWaitsForSharedAdmission(t *testing.T) {
	pki := testkit.NewPKI(t)
	f := makePKIFixture(t, interopPeer(t), pki)
	for _, network := range []string{"tcp", "udp"} {
		for _, mode := range []string{"local", "peer-while-waiting", "cancel"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				renegotiate := "0"
				if mode == "peer-while-waiting" {
					renegotiate = "3"
				}
				port, echo := startDataPeer(t, f, network, "tls", false, "1.3", "AES-256-GCM", "--reneg-sec", renegotiate)
				limiter, err := client.NewHandshakeLimiter(1, 1)
				if err != nil {
					t.Fatal(err)
				}
				cfg := f.config(pki, network, "tls", port, false)
				cfg.HandshakeLimiter, cfg.RekeyInterval = limiter, time.Second
				var observer admissionObserver
				cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, name, address string) (transport.PacketConn, error) {
					link, err := (transport.SocketDialer{}).DialPacket(ctx, name, address)
					if err != nil {
						return nil, err
					}
					observer.PacketConn = link
					return &observer, nil
				})
				tunnel, err := client.New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { tunnel.Close() })
				if err := tunnel.Connect(t.Context()); err != nil {
					t.Fatal(err)
				}
				info, ok := tunnel.ControlInfo()
				if !ok {
					t.Fatal("missing verified connection")
				}
				device, app := testkit.PacketPipe(8, transport.DefaultPacketSize)
				ctx, cancel := context.WithCancel(t.Context())
				running := make(chan struct{})
				go func() {
					defer close(running)
					tunnel.Run(ctx, device)
				}()
				t.Cleanup(func() {
					cancel()
					<-running
					device.Close()
					app.Close()
				})

				entered := make(chan struct{})
				blockerCfg := f.config(pki, network, "tls", port, false)
				blockerCfg.HandshakeLimiter = limiter
				blockerCfg.Dialer = testkit.DialerFunc(func(ctx context.Context, _, _ string) (transport.PacketConn, error) {
					close(entered)
					<-ctx.Done()
					return nil, ctx.Err()
				})
				blocker, err := client.New(blockerCfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { blocker.Close() })
				hold, release := context.WithCancel(t.Context())
				defer release()
				released := make(chan struct{})
				go func() {
					defer close(released)
					blocker.Connect(hold)
				}()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("limiter blocker did not enter")
				}
				awaitAdmissionCondition(t, 2*time.Second, func() bool { return limiter.Stats().Waiting == 1 })
				roundtrip(t, app, echo, info.TunnelIP.AsSlice(), []byte("old key while waiting"))
				if mode == "peer-while-waiting" {
					awaitAdmissionCondition(t, 4*time.Second, func() bool { return observer.first.Load() != 0 })
					if observer.first.Load() != 1 {
						t.Fatal("client sent a reset before the arriving peer reset was admitted")
					}
					roundtrip(t, app, echo, info.TunnelIP.AsSlice(), []byte("old key after peer reset"))
				}
				if sent := observer.writes.Load(); sent != 0 {
					t.Fatalf("sent %d soft resets before admission", sent)
				}
				if mode == "cancel" {
					cancel()
					select {
					case <-running:
					case <-time.After(2 * time.Second):
						t.Fatal("cancel did not join queued rekey")
					}
					if stats := limiter.Stats(); stats.Waiting != 0 || stats.InFlight != 1 {
						t.Fatalf("queued admission survived cancellation: %+v", stats)
					}
				}
				release()
				<-released
				if mode != "cancel" {
					waitForKeyID(t, tunnel, 1)
					roundtrip(t, app, echo, info.TunnelIP.AsSlice(), []byte("new key after admission"))
					reports := tunnel.RekeyReports()
					if len(reports) == 0 || reports[0].Code != "" || reports[0].PeerInitiated != (mode == "peer-while-waiting") {
						t.Fatalf("unexpected first rekey: %+v", reports)
					}
					cancel()
					<-running
				}
				if stats := limiter.Stats(); stats.InFlight != 0 || stats.Waiting != 0 || stats.Rejected != 0 || stats.PeakInFlight != 1 {
					t.Fatalf("leaked rekey admission: %+v", stats)
				}
			})
		}
	}
}

func awaitAdmissionCondition(t *testing.T, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for !ready() {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("admission condition timed out")
		}
	}
}
