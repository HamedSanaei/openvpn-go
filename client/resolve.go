package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/hamedsanaei/openvpn-go/transport"
)

// Resolver supplies ordered IPv4 and/or IPv6 candidates for every new dial.
// LookupNetIP must honor ctx and uses net.Resolver's network arguments.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ResolveUntilDialDeadline retries DNS failures until the socket deadline.
const ResolveUntilDialDeadline time.Duration = -1

var errResolution = errors.New("OpenVPN endpoint resolution failed")

func (c *Client) resolve(ctx context.Context, endpoint Endpoint) ([]string, error) {
	resolver, retry := c.config.Resolver, c.config.ResolveRetry
	if resolver == nil && retry == 0 && !endpoint.LocalAddress.IsValid() {
		return []string{endpoint.Host}, nil
	}
	if ip, err := netip.ParseAddr(endpoint.Host); err == nil {
		return []string{ip.Unmap().String()}, nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	family := endpoint.addressFamily()
	lookupCtx := ctx
	if retry > 0 {
		var cancel context.CancelFunc
		lookupCtx, cancel = context.WithTimeout(ctx, retry)
		defer cancel()
	}
	for {
		addresses, err := resolver.LookupNetIP(lookupCtx, family, endpoint.Host)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if lookupCtx.Err() != nil {
			return nil, errResolution
		}
		if err == nil {
			if candidates := resolvedHosts(addresses, family); len(candidates) != 0 {
				return candidates, nil
			}
		}
		if retry == 0 {
			return nil, errResolution
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-lookupCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, errResolution
		case <-timer.C:
		}
	}
}

func resolvedHosts(addresses []netip.Addr, family string) []string {
	const limit = 16
	var result []string
	seen := make(map[netip.Addr]bool, limit)
	for _, address := range addresses {
		addr := address.Unmap()
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() ||
			family == "ip4" && !addr.Is4() || family == "ip6" && !addr.Is6() || seen[addr] {
			continue
		}
		seen[addr] = true
		result = append(result, addr.String())
		if len(result) == limit {
			break
		}
	}
	return result
}

func (e Endpoint) addressFamily() string {
	switch {
	case strings.HasSuffix(e.Network, "4"), e.LocalAddress.Is4():
		return "ip4"
	case strings.HasSuffix(e.Network, "6"), e.LocalAddress.Is6():
		return "ip6"
	default:
		return "ip"
	}
}

func (e Endpoint) socketDialer(limit int) transport.Dialer {
	dialer := net.Dialer{}
	ip := net.IP(e.LocalAddress.AsSlice())
	if strings.HasPrefix(e.Network, "udp") {
		dialer.LocalAddr = &net.UDPAddr{IP: ip, Port: int(e.LocalPort), Zone: e.LocalAddress.Zone()}
	} else {
		dialer.LocalAddr = &net.TCPAddr{IP: ip, Port: int(e.LocalPort), Zone: e.LocalAddress.Zone()}
	}
	return (transport.SocketDialer{MaxPacketSize: limit}).WithDialContext(dialer.DialContext)
}

func (e Endpoint) hasLocalBind() bool { return e.LocalAddress.IsValid() || e.LocalPort != 0 }

func (c *Client) connectSocket(ctx context.Context, endpoint Endpoint, visit int) (transport.PacketConn, string, error) {
	dialer := c.config.Dialer
	if endpoint.hasLocalBind() {
		dialer = endpoint.socketDialer(c.config.MaxPacketSize)
	}
	hosts, err := c.resolve(ctx, endpoint)
	if err != nil {
		return nil, "", errors.Join(errResolution, err)
	}
	// A UDP socket can connect before its remote has replied. On a
	// subsequent visit start with a different address from the fresh lookup.
	if !strings.HasPrefix(endpoint.Network, "udp") {
		visit = 0
	}
	var lastErr error
	for i := range hosts {
		host := hosts[(visit+i)%len(hosts)]
		candidate := endpoint
		candidate.Host = host
		conn, err := dialer.DialPacket(ctx, candidate.Network, candidate.address())
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err == nil && conn != nil {
			tlsNetwork := endpoint.Network
			if addr, parseErr := netip.ParseAddr(host); parseErr == nil && addr.Unmap().Is6() &&
				(tlsNetwork == "tcp" || tlsNetwork == "udp") {
				tlsNetwork += "6"
			}
			return conn, tlsNetwork, nil
		}
		if conn != nil {
			conn.Close()
		}
		if err == nil || errors.Is(err, transport.ErrInvalidPacketLimit) ||
			errors.Is(err, transport.ErrUnsupportedNetwork) || errors.Is(err, transport.ErrInvalidConnection) {
			if err == nil {
				err = transport.ErrInvalidConnection
			}
			return nil, "", err
		}
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		lastErr = err
	}
	return nil, "", lastErr
}
