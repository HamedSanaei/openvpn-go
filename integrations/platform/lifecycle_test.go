package platform

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

type nativeTestDevice struct {
	tunnel.PacketConn
	closed *atomic.Int32
}

func (d nativeTestDevice) Close() error { d.closed.Add(1); return d.PacketConn.Close() }

func TestNetworkChangeJoinsPreviousLeaseAndCancellation(t *testing.T) {
	manager, err := sessions.New(sessions.Limits{Sessions: 1, PacketBytes: transport.DefaultPacketSize})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	use := make(chan struct{}, 2)
	changes := make(chan struct{}, 1)
	var opens, closed atomic.Int32
	pki := testkit.NewPKI(t)
	cfg := client.Config{Endpoints: []client.Endpoint{{Host: "127.0.0.1"}},
		TLS: &client.TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey},
		Dialer: testkit.DialerFunc(func(ctx context.Context, _ string, _ string) (transport.PacketConn, error) {
			use <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		})}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := Run(ctx, manager, "test-native", cfg, func(context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error) {
			if before := opens.Add(1) - 1; closed.Load() != before {
				return nil, nil, errors.New("previous native tunnel still open")
			}
			dev, _ := testkit.PacketPipe(1, 1024)
			return nativeTestDevice{dev, &closed}, nil, nil
		}, changes)
		finished <- err
	}()
	await := func() {
		t.Helper()
		select {
		case <-use:
		case err := <-finished:
			t.Fatalf("early finish: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	await()
	changes <- struct{}{}
	await()
	close(changes)
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) || opens.Load() != 2 || closed.Load() != 2 {
		t.Fatalf("native revocation: %v, opens=%d closes=%d", err, opens.Load(), closed.Load())
	}
}
