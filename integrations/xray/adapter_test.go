package xray

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/hamedsanaei/openvpn-go/client"
)

func TestTunnelAddressChangeStopsTraffic(t *testing.T) {
	expected := Addresses{IPv4: netip.MustParseAddr("10.49.0.2")}
	current := client.ControlInfo{TunnelIP: expected.IPv4}
	live := true
	device := &countingDevice{}
	guard := checkedDevice{
		PacketConn: device,
		expected:   expected,
		current:    func() (client.ControlInfo, bool) { return current, live },
	}
	if err := guard.WritePacket(t.Context(), []byte{1}); err != nil {
		t.Fatal(err)
	}
	live = false
	if !guard.check() {
		t.Fatal("transient disconnect blocked recovery")
	}
	live = true
	current.TunnelIP = netip.MustParseAddr("10.49.0.3")
	if _, err := guard.ReadPacket(t.Context(), make([]byte, 8)); !errors.Is(err, ErrTunnelAddress) {
		t.Fatalf("mismatched read: %v", err)
	}
	if err := guard.WritePacket(t.Context(), []byte{1}); !errors.Is(err, ErrTunnelAddress) || device.calls != 1 {
		t.Fatalf("a mismatched session reached the host device: %v", err)
	}
}

func TestCanceledAdapterClosesClientAndBorrowsDevice(t *testing.T) {
	device := &countingDevice{}
	adapter, err := New(client.Config{Endpoints: []client.Endpoint{{Host: "vpn.example.test"}}},
		device, Addresses{IPv4: netip.MustParseAddr("10.49.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := adapter.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled run: %v", err)
	}
	if adapter.Stats().State != client.StateClosed || device.closed {
		t.Fatal("adapter did not close the owned client or closed the borrowed device")
	}
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
}

type countingDevice struct {
	calls  int
	closed bool
}

func (d *countingDevice) ReadPacket(context.Context, []byte) (int, error) {
	d.calls++
	return 0, nil
}

func (d *countingDevice) WritePacket(context.Context, []byte) error {
	d.calls++
	return nil
}

func (d *countingDevice) Close() error {
	d.closed = true
	return nil
}
