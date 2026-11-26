package client

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

func BenchmarkIdleClient(b *testing.B) {
	pki := testkit.NewPKI(b)
	cfg := Config{Endpoints: fallbackEndpoints[:2], TLS: &TLSConfig{
		CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey,
	}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := New(cfg); err != nil {
			b.Fatal(err)
		}
	}

	// Sample retained heap with freshly constructed, undialed clients.
	// A batch amortizes runtime variation across the two post-GC samples.
	const count = 256
	var before, after runtime.MemStats
	clients := make([]*Client, count)
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range clients {
		c, err := New(cfg)
		if err != nil {
			b.Fatal(err)
		}
		clients[i] = c
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(clients)
	retained := max(float64(after.HeapAlloc)-float64(before.HeapAlloc), 0)
	b.ReportMetric(retained/count, "idle-B/client")
}

func BenchmarkReconnect(b *testing.B) {
	peers := make(chan transport.PacketConn, 1)
	cfg := Config{
		Endpoints: []Endpoint{testEndpoint},
		Retry:     RetryPolicy{InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond},
		Dialer: testkit.DialerFunc(func(ctx context.Context, _, _ string) (transport.PacketConn, error) {
			local, peer := testkit.PacketPipe(1, 64)
			select {
			case peers <- peer:
				return local, nil
			case <-ctx.Done():
				local.Close()
				return nil, ctx.Err()
			}
		}),
	}
	c, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	c.handshakes[0] = acceptTestSession
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()
	defer c.Close()
	if err := c.Connect(ctx); err != nil {
		b.Fatal(err)
	}
	device, app := testkit.PacketPipe(1, 64)
	defer app.Close()
	run := make(chan error, 1)
	go func() { run <- c.Run(ctx, device) }()
	first := <-peers
	// Synchronize with the first forwarding generation before timing loss.
	probe := []byte{1, 2, 3}
	dst := make([]byte, len(probe))
	deliver := func(peer transport.PacketConn) {
		b.Helper()
		step, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if err := app.WritePacket(step, probe); err != nil {
			b.Fatal(err)
		}
		if n, err := peer.ReadPacket(step, dst); err != nil || n != len(probe) {
			b.Fatalf("no forwarded probe after reconnect: %v", err)
		}
	}
	deliver(first)
	current := first
	b.ReportAllocs()
	for b.Loop() {
		current.Close()
		select {
		case current = <-peers:
		case err := <-run:
			b.Fatalf("forwarding stopped: %v", err)
		case <-time.After(time.Second):
			b.Fatal("no reconnect attempt")
		}
		deliver(current)
	}
	cancel()
	if err := <-run; !errors.Is(err, context.Canceled) {
		b.Fatalf("forwarding shutdown: %v", err)
	}
}
