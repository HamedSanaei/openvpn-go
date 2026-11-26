package sessions

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

type trackedDevice struct {
	tunnel.PacketConn
	count *atomic.Int32
}

func (d trackedDevice) Close() error { d.count.Add(1); return d.PacketConn.Close() }

func TestQuotasIsolationAndCleanup(t *testing.T) {
	m, err := New(Limits{Sessions: 3, PacketBytes: 2 * transport.DefaultPacketSize})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	pki := testkit.NewPKI(t)
	cfg := client.Config{Endpoints: []client.Endpoint{{Host: "127.0.0.1"}},
		TLS: &client.TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey}}
	entered := make(chan struct{}, 1)
	cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, _ string, _ string) (transport.PacketConn, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	var closed atomic.Int32
	factory := func(context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error) {
		device, _ := testkit.PacketPipe(1, 256)
		return trackedDevice{device, &closed}, nil, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	running, err := m.Start(ctx, "active", cfg, factory)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if lease, ok := m.Lookup("active"); !ok || lease != running {
		t.Fatal("active lease absent")
	}
	if _, err := m.Start(ctx, "active", cfg, factory); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	secondReady := make(chan struct{})
	failNow := make(chan struct{})
	failing, err := m.Start(ctx, "failed", cfg, func(ctx context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error) {
		dev, _, _ := factory(ctx)
		close(secondReady)
		select {
		case <-failNow:
		case <-ctx.Done():
		}
		return dev, nil, errors.New("private route failure")
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondReady:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := m.Start(ctx, "third", cfg, factory); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity: %v", err)
	}
	close(failNow)
	if status, err := failing.Wait(ctx); err != nil || !status.Done || status.Code != client.CodeTunnel ||
		running.Status().Done || closed.Load() != 1 {
		t.Fatalf("failed lease teardown or isolation: %+v %v", status, err)
	}
	running.Stop()
	if status, err := running.Wait(ctx); err != nil || status.Code != client.CodeCanceled || closed.Load() != 2 {
		t.Fatalf("canceled lease teardown: %+v %v", status, err)
	}
	m.Close()
	if _, err := m.Start(t.Context(), "active", cfg, factory); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
}
