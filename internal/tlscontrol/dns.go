package tlscontrol

import (
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/hamedsanaei/openvpn-go/tunnel"
)

const (
	maxDNSGroups    = 16
	maxDNSAddresses = 8
	maxDNSDomains   = 10
)

func dnsDomain(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if len(value) == 0 || len(value) > 253 {
		return "", false
	}
	for label := range strings.SplitSeq(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' ||
			strings.ContainsFunc(label, func(r rune) bool {
				return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-'
			}) {
			return "", false
		}
	}
	return value, true
}

func appendDomains(dst []string, values []string) ([]string, error) {
	if len(values) == 0 || len(dst)+len(values) > maxDNSDomains {
		return nil, ErrNegotiation
	}
	for _, value := range values {
		domain, ok := dnsDomain(value)
		if !ok || slices.Contains(dst, domain) {
			return nil, ErrNegotiation
		}
		dst = append(dst, domain)
	}
	return dst, nil
}

func (p *pushState) dhcpOption(args []string) error {
	if len(args) == 1 && args[0] == "DISABLE-NBT" {
		return nil
	}
	if len(args) < 2 {
		return ErrNegotiation
	}
	switch args[0] {
	case "DNS", "DNS6":
		addr, err := netip.ParseAddr(args[1])
		if len(args) != 2 || err != nil || !vpnAddress(addr, addr.Is4()) ||
			(args[0] == "DNS6" && addr.Is4()) || len(p.legacyDNS) == maxDNSAddresses {
			return ErrNegotiation
		}
		server := netip.AddrPortFrom(addr, 53)
		if slices.Contains(p.legacyDNS, server) {
			return ErrNegotiation
		}
		p.legacyDNS = append(p.legacyDNS, server)
	case "DOMAIN", "ADAPTER_DOMAIN_SUFFIX":
		domain, ok := dnsDomain(args[1])
		if len(args) != 2 || !ok || p.dns.Domain != "" {
			return ErrNegotiation
		}
		p.dns.Domain = domain
	case "DOMAIN-SEARCH":
		if len(args) != 2 {
			return ErrNegotiation
		}
		var err error
		p.dns.SearchDomains, err = appendDomains(p.dns.SearchDomains, args[1:])
		return err
	case "WINS", "NBDD", "NTP":
		addr, err := netip.ParseAddr(args[1])
		if len(args) != 2 || err != nil || !vpnAddress(addr, true) {
			return ErrNegotiation
		}
	case "NBT":
		if len(args) != 2 || args[1] != "1" && args[1] != "2" && args[1] != "4" && args[1] != "8" {
			return ErrNegotiation
		}
	case "NBT-SCOPE":
		if _, ok := dnsDomain(args[1]); len(args) != 2 || !ok {
			return ErrNegotiation
		}
	default:
		return ErrNegotiation
	}
	return nil
}

func (p *pushState) dnsOption(args []string) error {
	if len(args) >= 2 && args[0] == "search-domains" {
		var err error
		p.modernSearch, err = appendDomains(p.modernSearch, args[1:])
		return err
	}
	if len(args) < 4 || args[0] != "server" {
		return ErrNegotiation
	}
	index, err := strconv.ParseUint(args[1], 10, 7)
	if err != nil {
		return ErrNegotiation
	}
	id := uint8(index)
	server, exists := p.dnsGroups[id]
	if !exists && len(p.dnsGroups) == maxDNSGroups {
		return ErrNegotiation
	}
	server.Index = id
	values := args[3:]
	switch args[2] {
	case "address":
		if len(server.Addresses) != 0 || len(values) > maxDNSAddresses {
			return ErrNegotiation
		}
		for _, value := range values {
			endpoint, err := netip.ParseAddrPort(value)
			if err != nil {
				addr, err := netip.ParseAddr(value)
				if err != nil {
					return ErrNegotiation
				}
				// Port zero denotes the negotiated transport's default.
				endpoint = netip.AddrPortFrom(addr, 0)
			} else if endpoint.Port() == 0 {
				return ErrNegotiation
			}
			if !vpnAddress(endpoint.Addr(), endpoint.Addr().Is4()) || slices.Contains(server.Addresses, endpoint) {
				return ErrNegotiation
			}
			server.Addresses = append(server.Addresses, endpoint)
		}
	case "resolve-domains":
		if len(server.ResolveDomains) != 0 {
			return ErrNegotiation
		}
		server.ResolveDomains, err = appendDomains(nil, values)
		if err != nil {
			return err
		}
	case "transport":
		mode := tunnel.DNSTransport(values[0])
		if len(values) != 1 || server.Transport != "" ||
			(mode != tunnel.DNSPlain && mode != tunnel.DNSDoT && mode != tunnel.DNSDoH) {
			return ErrNegotiation
		}
		server.Transport = mode
	case "dnssec":
		mode := tunnel.DNSSECMode(values[0])
		if len(values) != 1 || server.DNSSEC != "" ||
			(mode != tunnel.DNSSECRequired && mode != tunnel.DNSSECOptional && mode != tunnel.DNSSECDisabled) {
			return ErrNegotiation
		}
		server.DNSSEC = mode
	case "sni":
		name, ok := dnsDomain(values[0])
		if len(values) != 1 || !ok || server.ServerName != "" {
			return ErrNegotiation
		}
		server.ServerName = name
	default:
		return ErrNegotiation
	}
	if p.dnsGroups == nil {
		p.dnsGroups = make(map[uint8]tunnel.DNSServer)
	}
	p.dnsGroups[id] = server
	return nil
}

func (p *pushState) finishDNS() error {
	if len(p.modernSearch) != 0 {
		p.dns.SearchDomains = p.modernSearch
	}
	for _, key := range slices.Sorted(maps.Keys(p.dnsGroups)) {
		group := p.dnsGroups[key]
		if len(group.Addresses) == 0 || (group.ServerName != "" && (group.Transport == "" || group.Transport == tunnel.DNSPlain)) {
			return ErrNegotiation
		}
		port := uint16(53)
		switch group.Transport {
		case tunnel.DNSDoT:
			port = 853
		case tunnel.DNSDoH:
			port = 443
		}
		unique := make(map[netip.AddrPort]bool, len(group.Addresses))
		for i, endpoint := range group.Addresses {
			if endpoint.Port() == 0 {
				endpoint = netip.AddrPortFrom(endpoint.Addr(), port)
			}
			if unique[endpoint] {
				return ErrNegotiation
			}
			unique[endpoint] = true
			group.Addresses[i] = endpoint
		}
		p.dns.Servers = append(p.dns.Servers, group)
	}
	if len(p.dns.Servers) == 0 && len(p.legacyDNS) != 0 {
		p.dns.Servers = []tunnel.DNSServer{{Addresses: p.legacyDNS}}
	}
	return nil
}
