package tlscontrol

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/hamedsanaei/openvpn-go/tunnel"
)

const pushBase = "PUSH_REPLY,peer-id 5,key-derivation tls-ekm,cipher AES-256-GCM"

func TestPushedIPv4RouteDefaultPlaceholders(t *testing.T) {
	p := pushState{allowed: []string{"AES-256-GCM"}}
	reply := pushBase + ",topology subnet,ifconfig 10.49.0.2 255.255.255.0,route-gateway 10.49.0.1,route-metric 21" +
		",route 10.20.1.2 default default default,route 10.21.1.2 255.255.0.0 default 2" +
		",route 10.22.1.2 default 10.49.0.9 default,route 10.23.1.2 default vpn_gateway 0"
	if done, err := p.add([]byte(reply)); !done || err != nil {
		t.Fatalf("valid pushed route defaults: done = %v, %v", done, err)
	}
	routes := p.Tunnel.Routes()
	if len(routes) != 4 || routes[0].Destination.String() != "10.20.1.2/32" || routes[0].Gateway.IsValid() ||
		!routes[0].HasMetric || routes[0].Metric != 21 || routes[1].Destination.String() != "10.21.0.0/16" ||
		routes[1].Gateway.IsValid() || routes[1].Metric != 2 || routes[2].Gateway.String() != "10.49.0.9" ||
		routes[2].Metric != 21 || routes[3].Gateway.IsValid() || !routes[3].HasMetric || routes[3].Metric != 0 {
		t.Fatalf("unexpected negotiated routes: %+v", routes)
	}
	for _, bad := range []string{
		"route 10.20.1.2 255.0.255.0", "route 10.20.1.2 default fd49::1",
		"route 10.20.1.2 default net_gateway", "route 10.20.1.2 default gateway.example.test",
		"route 10.20.1.2 default default 4294967296", "route-ipv6 fd42::/64 vpn_gateway default",
		"route 10.21.1.2 255.255.0.0,route 10.21.4.5 255.255.0.0 default default",
	} {
		p := pushState{allowed: []string{"AES-256-GCM"}}
		if done, err := p.add([]byte(pushBase + "," + bad)); done || err != ErrNegotiation {
			t.Fatalf("invalid route %q: done = %v, %v", bad, done, err)
		}
	}
}

func TestAuthenticatedTunnelPush(t *testing.T) {
	p := pushState{allowed: []string{"AES-256-GCM"}}
	first := pushBase + ",ifconfig 10.49.0.2 255.255.255.0,ifconfig-ipv6 fd49::2/64 fd49::1,route 10.52.0.2 255.255.0.0 vpn_gateway 12,dns server 3 resolve-domains corp.example,dns server 3 transport DoT,push-continuation 2"
	second := "PUSH_REPLY,topology subnet,route-gateway 10.49.0.1,route-ipv6-gateway fd49::1,route-ipv6 fd55::/48,dns server 3 address fd49::1,dns server 3 sni resolver.example,dns server 3 dnssec yes,dhcp-option DNS 10.49.0.1,dhcp-option DOMAIN example.test,dns search-domains corp.example example.test,tun-mtu 1380,push-continuation 1"
	if done, err := p.add([]byte(first)); done || err != nil {
		t.Fatalf("first part = %v, %v", done, err)
	}
	if done, err := p.add([]byte(second)); !done || err != nil {
		t.Fatalf("last part = %v, %v", done, err)
	}
	cfg := p.Tunnel
	if cfg.IPv4.String() != "10.49.0.2/24" || cfg.IPv6.String() != "fd49::2/64" ||
		cfg.GatewayIPv4.String() != "10.49.0.1" || cfg.GatewayIPv6.String() != "fd49::1" ||
		cfg.IPv6Peer.String() != "fd49::1" || cfg.Topology != tunnel.TopologySubnet || cfg.MTU != 1380 {
		t.Fatalf("tunnel fields = %+v", cfg)
	}
	routes, dns := cfg.Routes(), cfg.DNS()
	if len(routes) != 2 || routes[0].Destination.String() != "10.52.0.0/16" ||
		routes[0].Gateway.IsValid() || !routes[0].HasMetric || routes[0].Metric != 12 ||
		routes[1].Destination.String() != "fd55::/48" {
		t.Fatalf("routes = %+v", routes)
	}
	if len(dns.Servers) != 1 || dns.Servers[0].Index != 3 || dns.Servers[0].Addresses[0].String() != "[fd49::1]:853" ||
		dns.Servers[0].ResolveDomains[0] != "corp.example" || dns.Servers[0].Transport != tunnel.DNSDoT ||
		dns.Servers[0].DNSSEC != tunnel.DNSSECRequired || dns.Servers[0].ServerName != "resolver.example" ||
		dns.Domain != "example.test" || len(dns.SearchDomains) != 2 {
		t.Fatalf("DNS = %+v", dns)
	}
	routes[0].Destination = netip.Prefix{}
	dns.Servers[0].Addresses[0] = netip.AddrPort{}
	dns.Servers[0].ResolveDomains[0] = "changed"
	dns.SearchDomains[0] = "changed"
	if !cfg.Routes()[0].Destination.IsValid() || !cfg.DNS().Servers[0].Addresses[0].IsValid() ||
		cfg.DNS().Servers[0].ResolveDomains[0] != "corp.example" || cfg.DNS().SearchDomains[0] != "corp.example" {
		t.Fatal("snapshot aliases caller-owned slices")
	}
}

func TestTunnelPushRejectsMalformedAndDuplicate(t *testing.T) {
	for _, input := range []string{
		"ifconfig 10.0.0.2 255.0.255.0,topology subnet",
		"ifconfig 10.0.0.2 10.0.0.6,topology net30",
		"ifconfig 10.0.0.0 10.0.0.1,topology net30",
		"ifconfig 10.0.0.1 10.0.0.3,topology net30",
		"ifconfig 10.0.0.0 255.255.255.0,topology subnet",
		"ifconfig 10.0.0.255 255.255.255.0,topology subnet",
		"ifconfig-ipv6 ::ffff:10.0.0.2/120 fd49::1",
		"route 10.0.0.0 255.0.255.0",
		"route 10.0.0.1 255.0.0.0,route 10.0.0.2 255.0.0.0",
		"route-ipv6 fd49::/64 10.0.0.1",
		"route-gateway 10.0.0.1,route-gateway 10.0.0.1",
		"tun-mtu 1280,tun-mtu 1300",
		"ifconfig-ipv6 fd49::2/64 fd49::1,tun-mtu 1000",
		"dhcp-option DNS synthetic-secret.example",
		"dhcp-option DNS 127.0.0.1",
		"dhcp-option DOMAIN bad_domain",
		"dhcp-option UNKNOWN_OPTION synthetic",
		"dhcp-option WINS invalid",
		"dhcp-option DISABLE-NBT trailing",
		"dhcp-option DOMAIN-SEARCH A.example,dhcp-option DOMAIN-SEARCH a.example.",
		"dns server 1 transport DoT",
		"dns server 129 address 10.49.0.1",
		"dns server 3 address 10.49.0.1 10.49.0.1:53",
	} {
		p := pushState{allowed: []string{"AES-256-GCM"}}
		if done, err := p.add([]byte(pushBase + "," + input)); done || err == nil || strings.Contains(err.Error(), input) {
			t.Fatalf("accepted or leaked malformed push %q: %v, %v", input, done, err)
		}
	}
}

func TestTunnelPushPolicy(t *testing.T) {
	p := pushState{allowed: []string{"AES-256-GCM"}, policy: tunnel.PushPolicy{
		Addresses: tunnel.PushIgnore, DNS: tunnel.PushIgnore, Routes: tunnel.PushIgnore, MTU: tunnel.PushIgnore,
	}}
	if done, err := p.add([]byte(pushBase + ",ifconfig ignored,dhcp-option UNKNOWN_OPTION ignored,route ignored,tun-mtu ignored")); !done || err != nil {
		t.Fatalf("ignored payload = %v, %v", done, err)
	}
	if cfg := p.Tunnel; cfg.IPv4.IsValid() || len(cfg.DNS().Servers) != 0 || len(cfg.Routes()) != 0 || cfg.MTU != 0 {
		t.Fatal("ignored fields escaped into the configuration")
	}
	p = pushState{allowed: []string{"AES-256-GCM"}, policy: tunnel.PushPolicy{DNS: tunnel.PushReject}}
	if done, err := p.add([]byte(pushBase + ",dhcp-option DNS 10.0.0.1")); done || err != ErrNegotiation {
		t.Fatalf("rejected payload = %v, %v", done, err)
	}
	p = pushState{allowed: []string{"AES-256-GCM"}, policy: tunnel.PushPolicy{Routes: tunnel.PushIgnore}}
	if done, err := p.add([]byte(pushBase + ",up synthetic-secret")); done || err != ErrNegotiation {
		t.Fatal("policy weakened unrelated push restrictions")
	}
}

func TestRedirectGatewayAdvisoryPolicies(t *testing.T) {
	for _, tt := range []struct {
		flags  string
		action tunnel.PushAction
		accept bool
	}{
		{"", tunnel.PushAccept, true},
		{" local def1 bypass-dhcp bypass-dns block-local", tunnel.PushAccept, true},
		{" autolocal ipv6 !ipv4", tunnel.PushAccept, true},
		{" def1 ipv6 !ipv4", tunnel.PushAccept, true},
		{" local autolocal", tunnel.PushAccept, false},
		{" !ipv4", tunnel.PushAccept, false},
		{" ipv6 ipv6", tunnel.PushAccept, false},
		{" flags-unknown", tunnel.PushAccept, false},
		{" flags-unknown", tunnel.PushIgnore, true},
		{" def1", tunnel.PushReject, false},
	} {
		p := pushState{allowed: []string{"AES-256-GCM"}, policy: tunnel.PushPolicy{Routes: tt.action}}
		done, err := p.add([]byte(pushBase + ",redirect-gateway" + tt.flags + ",tun-mtu 1400"))
		if done != tt.accept || (err == nil) != tt.accept {
			t.Fatalf("redirect-gateway%s with action %d: %t, %v", tt.flags, tt.action, done, err)
		}
		if tt.accept && (len(p.Tunnel.Routes()) != 0 || p.Tunnel.MTU != 1400) {
			t.Fatalf("advisory option changed the route list or hid a later push: %+v", p.Tunnel)
		}
	}
}

func TestDisabledPushPingTimersAndDuplicates(t *testing.T) {
	for _, option := range []string{"ping", "ping-restart", "ping-exit"} {
		p := pushState{allowed: []string{"AES-256-GCM"}}
		done, err := p.add([]byte(pushBase + "," + option + " 0"))
		if !done || err != nil || p.PingInterval != 0 || p.PingTimeout != 0 || p.PingExit {
			t.Fatalf("%s 0 did not disable the timer: %v", option, err)
		}
		p = pushState{allowed: []string{"AES-256-GCM"}}
		if done, err := p.add([]byte(pushBase + "," + option + " 0,push-continuation 2")); done || err != nil {
			t.Fatalf("initial push: %t, %v", done, err)
		}
		if done, err := p.add([]byte("PUSH_REPLY," + option + " 1,push-continuation 1")); done || err != ErrNegotiation {
			t.Fatalf("duplicate %s succeeded: %t, %v", option, done, err)
		}
	}
}
