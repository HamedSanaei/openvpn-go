package tunnel

import (
	"errors"
	"net/netip"
	"slices"
)

// ErrMTUExceeded reports an IP packet larger than the active tunnel MTU.
var ErrMTUExceeded = errors.New("IP packet exceeds the OpenVPN tunnel MTU")

// ValidMTU reports whether mtu is unset or within the supported IP range.
func ValidMTU(mtu int) bool { return mtu == 0 || mtu >= 68 && mtu <= 65535 }

// PushAction controls an authenticated class of optional push directives.
type PushAction uint8

const (
	PushAccept PushAction = iota
	PushIgnore
	PushReject
)

// PushPolicy controls metadata returned to the embedding application.
// The default validates and accepts supported options in each class.
type PushPolicy struct {
	Addresses PushAction
	Routes    PushAction
	DNS       PushAction
	MTU       PushAction
}

type Topology string

const (
	TopologySubnet Topology = "subnet"
	TopologyNet30  Topology = "net30"
	TopologyP2P    Topology = "p2p"
)

// Route describes a canonical destination. An unset gateway requests the
// default VPN gateway for the family. Metric is present only when HasMetric.
type Route struct {
	Destination netip.Prefix
	Gateway     netip.Addr
	Metric      uint32
	HasMetric   bool
}

type DNSTransport string
type DNSSECMode string

const (
	DNSPlain DNSTransport = "plain"
	DNSDoT   DNSTransport = "DoT"
	DNSDoH   DNSTransport = "DoH"

	DNSSECRequired DNSSECMode = "yes"
	DNSSECOptional DNSSECMode = "optional"
	DNSSECDisabled DNSSECMode = "no"
)

// DNSServer is an ordered server group. Empty ResolveDomains means all
// domains. An unset transport represents plain DNS. DNSSEC and server-name
// settings are metadata for the application resolver.
type DNSServer struct {
	Index          uint8
	Addresses      []netip.AddrPort
	ResolveDomains []string
	Transport      DNSTransport
	DNSSEC         DNSSECMode
	ServerName     string
}

type DNSConfig struct {
	Servers       []DNSServer
	Domain        string
	SearchDomains []string
}

// Configuration is a snapshot of the authenticated tunnel metadata.
// Address prefixes keep the assigned host address. An unset MTU or address
// means the peer supplied none or the configured push policy ignored it.
type Configuration struct {
	IPv4, IPv6               netip.Prefix
	IPv4Peer, IPv6Peer       netip.Addr
	GatewayIPv4, GatewayIPv6 netip.Addr
	Topology                 Topology
	MTU                      uint16

	options *networkOptions
}

type networkOptions struct {
	routes []Route
	dns    DNSConfig
}

// WithNetworkOptions returns a copy with its own routes and DNS options.
func (c Configuration) WithNetworkOptions(routes []Route, dns DNSConfig) Configuration {
	c.options = &networkOptions{routes: slices.Clone(routes), dns: dns.Clone()}
	return c
}

func (c Configuration) Routes() []Route {
	if c.options == nil {
		return nil
	}
	return slices.Clone(c.options.routes)
}

func (c Configuration) DNS() DNSConfig {
	if c.options == nil {
		return DNSConfig{}
	}
	return c.options.dns.Clone()
}

// Clone returns a detached copy of all server groups and domains.
func (d DNSConfig) Clone() DNSConfig {
	d.SearchDomains = slices.Clone(d.SearchDomains)
	d.Servers = slices.Clone(d.Servers)
	for i := range d.Servers {
		d.Servers[i].Addresses = slices.Clone(d.Servers[i].Addresses)
		d.Servers[i].ResolveDomains = slices.Clone(d.Servers[i].ResolveDomains)
	}
	return d
}
