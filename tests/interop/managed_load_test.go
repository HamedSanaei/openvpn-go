//go:build linux

package interop_test

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/integrations/sessions"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

func init() {
	startManagedLoad = beginManagedLoad
	waitManagedLoad = awaitManagedLoad
}

func beginManagedLoad(t *testing.T, tunnels []loadTunnel) func(int, client.Config) {
	t.Helper()
	count := len(tunnels)
	limits := sessions.Limits{Sessions: count, PacketBytes: count * transport.DefaultPacketSize}
	budget := sessions.ResourceLimits{BufferBytes: int64(count) * (2 << 20), FileDescriptors: count}
	manager, err := sessions.NewWithResources(limits, budget)
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := client.NewHandshakeLimiter(8, count)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		manager.Close()
		for _, connection := range tunnels {
			if connection.app != nil {
				connection.app.Close()
			}
		}
		if usage := manager.Usage(); usage != (sessions.Usage{}) {
			t.Errorf("manager reservations survived cleanup: %+v", usage)
		}
		if stats := limiter.Stats(); stats.InFlight != 0 || stats.Waiting != 0 || stats.Rejected != 0 {
			t.Errorf("unexpected managed handshake admission: %+v", stats)
		}
	})
	adapter := sessions.AdapterReservation{BufferBytes: 16 * transport.DefaultPacketSize}
	return func(index int, cfg client.Config) {
		cfg.HandshakeLimiter = limiter
		var address atomic.Pointer[netip.Addr]
		device, app := testkit.PacketPipe(8, transport.DefaultPacketSize)
		configure := func(_ context.Context, g client.TunnelGeneration) (func(), error) {
			addr := g.Control.TunnelIP
			if !addr.Is4() {
				return nil, errors.New("missing managed tunnel IPv4 address")
			}
			address.Store(&addr)
			return func() { address.CompareAndSwap(&addr, nil) }, nil
		}
		lease, err := manager.StartWithResources(t.Context(), strconv.Itoa(index), cfg, adapter,
			func(context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error) {
				return device, configure, nil
			})
		if err != nil {
			device.Close()
			app.Close()
			t.Fatal(err)
		}
		tunnels[index] = loadTunnel{
			app: app,
			managedAddress: func() netip.Addr {
				if addr := address.Load(); addr != nil {
					return *addr
				}
				return netip.Addr{}
			},
			managedStatus: func() (client.Stats, bool) {
				status := lease.Status()
				return status.Stats, status.Done
			},
		}
	}
}

func awaitManagedLoad(t *testing.T, tunnels []loadTunnel) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for {
		ready := 0
		for i, tunnel := range tunnels {
			if stats, done := tunnel.managedStatus(); done {
				t.Fatalf("managed tunnel %d stopped during admission: %s", i, stats.LastError)
			}
			if tunnel.address().Is4() {
				ready++
			}
		}
		if ready == len(tunnels) {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("only %d/%d managed tunnels connected", ready, len(tunnels))
		}
	}
}
