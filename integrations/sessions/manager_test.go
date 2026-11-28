package sessions

import (
	"context"
	"errors"
	"math"
	"net"
	"strconv"
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

func TestExplicitResourceBudgetBeyondLegacyLimit(t *testing.T) {
	const leases = 65
	limits := Limits{Sessions: leases + 1, PacketBytes: (leases + 1) * transport.DefaultPacketSize}
	if _, err := New(limits); !errors.Is(err, ErrConfig) {
		t.Fatalf("unexpected legacy constructor result: %v", err)
	}
	m, err := NewWithResources(limits, ResourceLimits{BufferBytes: 128 << 20, FileDescriptors: 2 * leases})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	pki := testkit.NewPKI(t)
	cfg := client.Config{Endpoints: []client.Endpoint{{Host: "127.0.0.1"}}, ReceiveQueueSize: 4,
		TLS: &client.TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey}}
	device := func(ctx context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	adapter := AdapterReservation{BufferBytes: 2048, FileDescriptors: 1}
	var first *Lease
	for index := range leases {
		lease, err := m.StartWithResources(t.Context(), strconv.Itoa(index), cfg, adapter, device)
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			first = lease
		}
	}
	if _, err := m.Start(t.Context(), "overflow", cfg, device); !errors.Is(err, ErrCapacity) {
		t.Fatalf("descriptor admission: %v", err)
	}
	if u := m.Usage(); u.Sessions != leases || u.FileDescriptors != 2*leases || u.BufferBytes <= int64(u.PacketBytes) {
		t.Fatalf("reserved usage: %+v", u)
	}
	first.Stop()
	if _, err := first.Wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.StartWithResources(t.Context(), "overflow-bytes", cfg, AdapterReservation{BufferBytes: math.MaxInt64}, device); !errors.Is(err, ErrConfig) {
		t.Fatalf("invalid estimate: %v", err)
	}
	if _, err := m.StartWithResources(t.Context(), "overflow", cfg, adapter, device); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if u := m.Usage(); u != (Usage{}) {
		t.Fatalf("reservations remained after close: %+v", u)
	}
}

func (d trackedDevice) Close() error { d.count.Add(1); return d.PacketConn.Close() }

type cleanupDevice struct {
	trackedDevice
	err error
}

func (d cleanupDevice) Close() error {
	d.trackedDevice.Close()
	return d.err
}

func TestLeaseReportsDeviceCleanupIndependently(t *testing.T) {
	for _, tc := range []struct {
		name        string
		factoryFail bool
		closeErr    error
		code        client.ErrorCode
		failed      bool
	}{
		{"cancel", false, errors.New("private cleanup failure"), client.CodeCanceled, true},
		{"partial_factory", true, errors.New("private cleanup failure"), client.CodeTunnel, true},
		{"already_closed", false, net.ErrClosed, client.CodeCanceled, false},
		{"joined_cleanup", false, errors.Join(net.ErrClosed, errors.New("private cleanup failure")), client.CodeCanceled, true},
		{"success", false, nil, client.CodeCanceled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, err := New(Limits{Sessions: 1, PacketBytes: transport.DefaultPacketSize})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			pki := testkit.NewPKI(t)
			entered := make(chan struct{}, 1)
			cfg := client.Config{
				Endpoints: []client.Endpoint{{Host: "127.0.0.1"}},
				TLS:       &client.TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey},
				Dialer: testkit.DialerFunc(func(ctx context.Context, _, _ string) (transport.PacketConn, error) {
					entered <- struct{}{}
					<-ctx.Done()
					return nil, ctx.Err()
				}),
			}
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			var closes atomic.Int32
			lease, err := manager.Start(ctx, "reusable", cfg, func(context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error) {
				raw, _ := testkit.PacketPipe(1, 64)
				device := cleanupDevice{trackedDevice{raw, &closes}, tc.closeErr}
				if tc.factoryFail {
					return device, nil, errors.New("private factory failure")
				}
				return device, nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !tc.factoryFail {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				lease.Stop()
			}
			status, err := lease.Wait(ctx)
			if err != nil || status.Code != tc.code || status.Cleanup != (CleanupStatus{DeviceFailed: tc.failed}) ||
				closes.Load() != 1 || manager.Usage() != (Usage{}) {
				t.Fatalf("unexpected completed lease: %+v, %v", status, err)
			}
			again, err := manager.Start(ctx, "reusable", cfg, func(context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error) {
				return nil, nil, errors.New("test stop")
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := again.Wait(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

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
