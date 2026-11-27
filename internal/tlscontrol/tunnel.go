package tlscontrol

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/hamedsanaei/openvpn-go/tunnel"
)

func (p *pushState) tunnelOption(name, value string) error {
	var action tunnel.PushAction
	switch name {
	case "tun-ipv6", "topology", "ifconfig", "ifconfig-ipv6":
		action = p.policy.Addresses
	case "route", "route-ipv6", "route-gateway", "route-ipv6-gateway", "redirect-gateway":
		action = p.policy.Routes
	case "dhcp-option", "dns", "block-outside-dns":
		action = p.policy.DNS
	case "tun-mtu":
		action = p.policy.MTU
	default:
		return ErrNegotiation
	}
	if action == tunnel.PushReject || len(value) > 1024 ||
		strings.ContainsFunc(value, func(r rune) bool { return r != '\t' && unicode.IsControl(r) }) ||
		!validKeyString(value) {
		return ErrNegotiation
	}
	if action == tunnel.PushIgnore {
		return nil
	}
	args := strings.Fields(value)
	switch name {
	case "tun-ipv6", "block-outside-dns":
		if len(args) != 0 {
			return ErrNegotiation
		}
	case "topology":
		top := tunnel.Topology(value)
		if p.Tunnel.Topology != "" || (top != tunnel.TopologySubnet && top != tunnel.TopologyNet30 && top != tunnel.TopologyP2P) {
			return ErrNegotiation
		}
		p.Tunnel.Topology = top
	case "ifconfig", "ifconfig-ipv6":
		return p.address(name == "ifconfig", args)
	case "route", "route-ipv6":
		return p.route(name == "route", args)
	case "route-gateway":
		return setGateway(&p.Tunnel.GatewayIPv4, true, args)
	case "route-ipv6-gateway":
		return setGateway(&p.Tunnel.GatewayIPv6, false, args)
	case "tun-mtu":
		mtu, err := strconv.ParseUint(value, 10, 16)
		if err != nil || mtu < 68 || p.Tunnel.MTU != 0 {
			return ErrNegotiation
		}
		p.Tunnel.MTU = uint16(mtu)
	case "dhcp-option":
		return p.dhcpOption(args)
	case "dns":
		return p.dnsOption(args)
	case "redirect-gateway":
		// This is a host routing command. Explicit numeric routes are
		// represented separately and routing remains caller-owned.
	}
	return nil
}

func vpnAddress(a netip.Addr, ipv4 bool) bool {
	return a.IsValid() && a.Is4() == ipv4 && !a.Is4In6() && a.Zone() == "" &&
		(a.IsGlobalUnicast() || a.IsLinkLocalUnicast())
}

func (p *pushState) address(ipv4 bool, args []string) error {
	if len(args) != 2 {
		return ErrNegotiation
	}
	second, err := netip.ParseAddr(args[1])
	if err != nil || second.Is4() != ipv4 || second.Is4In6() || second.Zone() != "" {
		return ErrNegotiation
	}
	if ipv4 {
		addr, err := netip.ParseAddr(args[0])
		if err != nil || !vpnAddress(addr, true) || p.ipv4.IsValid() {
			return ErrNegotiation
		}
		p.ipv4, p.ipv4Param = addr, second
		return nil
	}
	prefix, err := netip.ParsePrefix(args[0])
	if err != nil || !vpnAddress(prefix.Addr(), false) || !vpnAddress(second, false) ||
		prefix.Addr() == second || p.Tunnel.IPv6.IsValid() {
		return ErrNegotiation
	}
	p.Tunnel.IPv6, p.Tunnel.IPv6Peer = prefix, second
	return nil
}

func maskBits(addr netip.Addr) int {
	if !addr.Is4() {
		return -1
	}
	mask := addr.As4()
	ones, bits := net.IPMask(mask[:]).Size()
	if bits != 32 {
		return -1
	}
	return ones
}

func setGateway(dst *netip.Addr, ipv4 bool, args []string) error {
	if len(args) != 1 || dst.IsValid() {
		return ErrNegotiation
	}
	addr, err := netip.ParseAddr(args[0])
	if err != nil || !vpnAddress(addr, ipv4) {
		return ErrNegotiation
	}
	*dst = addr
	return nil
}

func (p *pushState) route(ipv4 bool, args []string) error {
	if len(args) == 0 || len(p.routes) >= 128 {
		return ErrNegotiation
	}
	var destination netip.Prefix
	if ipv4 {
		addr, err := netip.ParseAddr(args[0])
		if err != nil || !addr.Is4() {
			return ErrNegotiation
		}
		bits := 32
		if len(args) > 1 {
			mask, err := netip.ParseAddr(args[1])
			bits = maskBits(mask)
			if err != nil || bits < 0 {
				return ErrNegotiation
			}
			args = args[1:]
		}
		destination = netip.PrefixFrom(addr, bits)
	} else {
		var err error
		destination, err = netip.ParsePrefix(args[0])
		if err != nil || !destination.Addr().Is6() || destination.Addr().Is4In6() || destination.Addr().Zone() != "" {
			return ErrNegotiation
		}
	}
	args = args[1:]
	dest := destination.Masked()
	if len(args) > 2 || slices.ContainsFunc(p.routes, func(route tunnel.Route) bool { return route.Destination == dest }) {
		return ErrNegotiation
	}
	route := tunnel.Route{Destination: dest}
	if len(args) != 0 && args[0] != "vpn_gateway" {
		if err := setGateway(&route.Gateway, ipv4, args[:1]); err != nil {
			return err
		}
	}
	if len(args) == 2 {
		metric, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil {
			return ErrNegotiation
		}
		route.Metric, route.HasMetric = uint32(metric), true
	}
	p.routes = append(p.routes, route)
	return nil
}

func usableSubnetHost(addr netip.Addr, bits int) bool {
	if bits >= 31 {
		return true
	}
	raw := addr.As4()
	mask := uint32(1)<<(32-bits) - 1
	host := binary.BigEndian.Uint32(raw[:]) & mask
	return host != 0 && host != mask
}

func (p *pushState) finishTunnel() error {
	if p.ipv4.IsValid() {
		if p.Tunnel.Topology == "" {
			p.Tunnel.Topology = tunnel.TopologyNet30
			if maskBits(p.ipv4Param) >= 0 {
				p.Tunnel.Topology = tunnel.TopologySubnet
			}
		}
		switch p.Tunnel.Topology {
		case tunnel.TopologySubnet:
			bits := maskBits(p.ipv4Param)
			if bits < 0 || !usableSubnetHost(p.ipv4, bits) {
				return ErrNegotiation
			}
			p.Tunnel.IPv4 = netip.PrefixFrom(p.ipv4, bits)
		default:
			bits := 32
			if p.Tunnel.Topology == tunnel.TopologyNet30 {
				bits = 30
			}
			prefix := netip.PrefixFrom(p.ipv4, bits)
			if !vpnAddress(p.ipv4Param, true) || p.ipv4 == p.ipv4Param ||
				(bits == 30 && (!prefix.Contains(p.ipv4Param) ||
					!usableSubnetHost(p.ipv4, bits) || !usableSubnetHost(p.ipv4Param, bits))) {
				return ErrNegotiation
			}
			p.Tunnel.IPv4, p.Tunnel.IPv4Peer = prefix, p.ipv4Param
		}
	}
	if p.Tunnel.IPv6.IsValid() && p.Tunnel.MTU != 0 && p.Tunnel.MTU < 1280 {
		return ErrNegotiation
	}
	if err := p.finishDNS(); err != nil {
		return err
	}
	p.Tunnel = p.Tunnel.WithNetworkOptions(p.routes, p.dns)
	return nil
}
