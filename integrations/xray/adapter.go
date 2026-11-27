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

// Addresses identifies fixed addresses provisioned by the host.
type Addresses struct {
	IPv4 netip.Addr
	IPv6 netip.Prefix
}

func (a Addresses) valid() bool {
	return (a.IPv4.IsValid() || a.IPv6.IsValid()) &&
		(!a.IPv4.IsValid() || a.IPv4.Is4() && a.IPv4.IsGlobalUnicast()) &&
		(!a.IPv6.IsValid() || a.IPv6.Addr().Is6() && !a.IPv6.Addr().Is4In6() && a.IPv6.Addr().IsGlobalUnicast())
}

func (a Addresses) matches(info client.ControlInfo) bool {
	return a.IPv4 == info.TunnelIP && a.IPv6 == info.TunnelIPv6
}

// Options supplies application-owned configuration and DNS socket handling.
type Options struct {
	Configure client.TunnelConfigurer
	DNSDialer DNSDialer
	// MSSMTU enables TCP MSS clamping using this inner IP MTU ceiling.
	// An authenticated smaller generation MTU takes precedence.
	MSSMTU int
}

// Adapter owns a single OpenVPN client and borrows a packet device.
type Adapter struct {
	client  *client.Client
	device  tunnel.PacketConn
	options Options
	fixed   *Addresses
	mss     *mssDevice
	started atomic.Bool
	dns     atomic.Pointer[dnsScope]
}

// New uses an already configured device with fixed tunnel addresses.
func New(cfg client.Config, device tunnel.PacketConn, addresses Addresses) (*Adapter, error) {
	return NewFixed(cfg, device, addresses, Options{})
}

// NewFixed uses fixed host addresses with optional adapter settings.
func NewFixed(cfg client.Config, device tunnel.PacketConn, addresses Addresses, opts Options) (*Adapter, error) {
	if !addresses.valid() || addresses.IPv6.IsValid() && opts.MSSMTU != 0 && opts.MSSMTU < 1280 {
		return nil, ErrTunnelConfig
	}
	return newAdapter(cfg, device, &addresses, opts)
}

// NewConfigured lets the caller prepare and roll back the device and its
// routes for each connection, including a changed assignment on reconnect.
func NewConfigured(cfg client.Config, device tunnel.PacketConn, opts Options) (*Adapter, error) {
	if opts.Configure == nil {
		return nil, ErrTunnelConfig
	}
	return newAdapter(cfg, device, nil, opts)
}

func newAdapter(cfg client.Config, device tunnel.PacketConn, fixed *Addresses, opts Options) (*Adapter, error) {
	if device == nil || !tunnel.ValidMTU(opts.MSSMTU) {
		return nil, ErrTunnelConfig
	}
	c, err := client.New(cfg)
	if err != nil {
		return nil, err
	}
	a := &Adapter{client: c, device: device, options: opts, fixed: fixed}
	if opts.MSSMTU != 0 {
		a.mss = &mssDevice{PacketConn: device}
		a.device = a.mss
	}
	return a, nil
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
	mismatch := false
	err := a.client.RunConfigured(ctx, a.device, func(ctx context.Context, gen client.TunnelGeneration) (func(), error) {
		if a.fixed != nil && !a.fixed.matches(gen.Control) {
			mismatch = true
			return nil, ErrTunnelAddress
		}
		return a.prepare(ctx, gen)
	})
	var failure *client.Error
	if mismatch && errors.As(err, &failure) && failure.Code == client.CodeTunnel {
		return ErrTunnelAddress
	}
	return err
}

func (a *Adapter) prepare(ctx context.Context, gen client.TunnelGeneration) (func(), error) {
	mtu := a.options.MSSMTU
	if a.mss != nil {
		if gen.Control.MaxTunnelPacketSize > 0 {
			mtu = min(mtu, gen.Control.MaxTunnelPacketSize)
		}
		if gen.Control.TunnelIPv6.IsValid() && mtu < 1280 {
			return nil, ErrTunnelConfig
		}
	}
	var rollback func()
	if a.options.Configure != nil {
		var err error
		rollback, err = a.options.Configure(ctx, gen)
		if err != nil || ctx.Err() != nil {
			return rollback, err
		}
	}
	if a.mss != nil {
		a.mss.mtu.Store(int32(mtu))
	}
	if a.options.DNSDialer == nil {
		return rollback, nil
	}
	scope := &dnsScope{ctx: ctx, generation: gen.Number, config: gen.Control.Tunnel.DNS(), connections: make(map[*dnsConn]struct{})}
	a.dns.Store(scope)
	return func() {
		a.dns.CompareAndSwap(scope, nil)
		scope.close()
		if rollback != nil {
			rollback()
		}
	}, nil
}

// Close interrupts the owned client. The caller closes the borrowed device.
func (a *Adapter) Close() error { return a.client.Close() }

// Stats returns the core's redacted lifecycle and traffic counters.
func (a *Adapter) Stats() client.Stats { return a.client.Stats() }
