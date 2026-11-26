// Package xray connects a host-owned IP tunnel to the public OpenVPN client.
package xray

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

var (
	ErrTunnelAddress = errors.New("OpenVPN negotiated different addresses from the host tunnel")
	ErrTunnelConfig  = errors.New("invalid host tunnel configuration")
)

// Addresses identifies the host's configured IPv4 address and IPv6 prefix.
// At least one family must be provisioned. The negotiated values must match
// exactly, including across reconnects.
type Addresses struct {
	IPv4 netip.Addr
	IPv6 netip.Prefix
}

func (a Addresses) valid() bool {
	return (a.IPv4.IsValid() || a.IPv6.IsValid()) &&
		(!a.IPv4.IsValid() || a.IPv4.Is4() && a.IPv4.IsGlobalUnicast()) &&
		(!a.IPv6.IsValid() || a.IPv6.Addr().Is6() && !a.IPv6.Addr().Is4In6() && a.IPv6.Addr().IsGlobalUnicast())
}

// Adapter owns a single OpenVPN client and borrows a packet device.
type Adapter struct {
	client  *client.Client
	device  *checkedDevice
	started atomic.Bool
}

func New(cfg client.Config, device tunnel.PacketConn, addresses Addresses) (*Adapter, error) {
	if device == nil || !addresses.valid() {
		return nil, ErrTunnelConfig
	}
	c, err := client.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Adapter{client: c, device: &checkedDevice{
		PacketConn: device, current: c.ControlInfo, expected: addresses,
	}}, nil
}

// Run connects, forwards and recovers until cancellation, terminal failure or
// exhaustion. It closes the client when forwarding ends. The device is borrowed.
func (a *Adapter) Run(ctx context.Context) error {
	if !a.started.CompareAndSwap(false, true) {
		return &client.Error{Op: "run", Code: client.CodeBusy}
	}
	defer a.client.Close()
	if err := a.client.Connect(ctx); err != nil {
		return err
	}
	if !a.device.check() {
		return ErrTunnelAddress
	}
	err := a.client.Run(ctx, a.device)
	var failure *client.Error
	if a.device.mismatch.Load() && errors.As(err, &failure) && failure.Code == client.CodeTunnel {
		return ErrTunnelAddress
	}
	return err
}

// Close interrupts the owned client. The caller closes the borrowed device.
func (a *Adapter) Close() error { return a.client.Close() }

// Stats returns the core's redacted lifecycle and traffic counters.
func (a *Adapter) Stats() client.Stats { return a.client.Stats() }

type checkedDevice struct {
	tunnel.PacketConn
	current  func() (client.ControlInfo, bool)
	expected Addresses
	mismatch atomic.Bool
}

func (d *checkedDevice) check() bool {
	info, live := d.current()
	if live && (info.TunnelIP != d.expected.IPv4 || info.TunnelIPv6 != d.expected.IPv6) {
		d.mismatch.Store(true)
	}
	return !d.mismatch.Load()
}

func (d *checkedDevice) ReadPacket(ctx context.Context, packet []byte) (int, error) {
	if !d.check() {
		return 0, ErrTunnelAddress
	}
	return d.PacketConn.ReadPacket(ctx, packet)
}

func (d *checkedDevice) WritePacket(ctx context.Context, packet []byte) error {
	if !d.check() {
		return ErrTunnelAddress
	}
	return d.PacketConn.WritePacket(ctx, packet)
}
