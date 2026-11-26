package xray

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/hamedsanaei/openvpn-go/client"
)

func TestFixedAddressesRequireAnExactAssignment(t *testing.T) {
	expected := Addresses{IPv4: netip.MustParseAddr("10.49.0.2")}
	current := client.ControlInfo{TunnelIP: expected.IPv4}
	if !expected.matches(current) {
		t.Fatal("expected the fixed assignment to match")
	}
	current.TunnelIP = netip.MustParseAddr("10.49.0.3")
	if expected.matches(current) {
		t.Fatal("changed IPv4 assignment matched")
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
