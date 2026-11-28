package client

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
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
			return nil, lookupCtx.Err()
		}
		if err == nil {
			if candidates := resolvedHosts(addresses, family); len(candidates) != 0 {
				return candidates, nil
			}
		}
		if retry == 0 {
			if contextCode(err, "") == CodeTimeout {
				return nil, context.DeadlineExceeded
			}
			return nil, errResolution
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-lookupCtx.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, lookupCtx.Err()
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
		if !validRemoteIP(addr, family) || seen[addr] {
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

func validRemoteIP(addr netip.Addr, family string) bool {
	addr = addr.Unmap()
	return addr.IsValid() && !addr.IsUnspecified() && !addr.IsMulticast() &&
		(family != "ip4" || addr.Is4()) && (family != "ip6" || addr.Is6())
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
	var local net.Addr
	ip := net.IP(e.LocalAddress.AsSlice())
	if strings.HasPrefix(e.Network, "udp") {
		local = &net.UDPAddr{IP: ip, Port: int(e.LocalPort), Zone: e.LocalAddress.Zone()}
	} else {
		local = &net.TCPAddr{IP: ip, Port: int(e.LocalPort), Zone: e.LocalAddress.Zone()}
	}
	return (transport.SocketDialer{MaxPacketSize: limit}).WithLocalAddr(local)
}

func (e Endpoint) hasLocalBind() bool { return e.LocalAddress.IsValid() || e.LocalPort != 0 }

type candidateCursor struct {
	host     string
	position int
}

func (c *Client) connectSocket(ctx context.Context, endpoint Endpoint, cursor *candidateCursor) (transport.PacketConn, string, error) {
	dialer := c.config.Dialer
	if endpoint.hasLocalBind() {
		dialer = endpoint.socketDialer(c.config.MaxPacketSize)
	}
	hosts, err := c.resolve(ctx, endpoint)
	if err != nil {
		return nil, "", errors.Join(errResolution, err)
	}
	// A socket can connect before OpenVPN has replied. Start after the
	// selected address when retrying with freshly resolved candidates.
	start := 0
	if cursor.host != "" {
		if previous := slices.Index(hosts, cursor.host); previous >= 0 {
			start = (previous + 1) % len(hosts)
		} else {
			start = min(cursor.position, len(hosts)-1)
		}
	}
	var lastErr error
	for i := range hosts {
		position := (start + i) % len(hosts)
		host := hosts[position]
		candidate := endpoint
		candidate.Host = host
		conn, err := dialer.DialPacket(ctx, candidate.Network, candidate.address())
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err == nil && conn != nil {
			tlsNetwork := endpoint.Network
			addr, _ := netip.ParseAddr(host)
			if !addr.IsValid() {
				if peer, ok := conn.(interface{ PeerIP() netip.Addr }); ok {
					addr = peer.PeerIP()
				}
			}
			if addr.Unmap().Is6() && (tlsNetwork == "tcp" || tlsNetwork == "udp") {
				tlsNetwork += "6"
			}
			*cursor = candidateCursor{host: host, position: position}
			return conn, tlsNetwork, nil
		}
		if conn != nil {
			conn.Close()
		}
		if err == nil || errors.Is(err, transport.ErrInvalidPacketLimit) ||
			errors.Is(err, transport.ErrUnsupportedNetwork) || errors.Is(err, transport.ErrInvalidConnection) ||
			errors.Is(err, transport.ErrPeerCertificate) {
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
