package tlscontrol

import (
	"github.com/hamedsanaei/openvpn-go/tunnel"
	"testing"
)

func TestAccessServerPushMetadata(t *testing.T) {
	p := pushState{allowed: []string{"AES-256-GCM"}}
	raw := pushBase + ",topology subnet,ifconfig 10.49.0.2 255.255.255.0,route-gateway 10.49.0.1,route-delay 5 30,route-metric 101,dhcp-pre-release,dhcp-renew,dhcp-release,register-dns,dhcp-option DNS 10.49.0.1,dhcp-option NBT 2,block-ipv6,route 10.20.0.0 255.255.0.0,route 10.21.0.0 255.255.0.0 vpn_gateway 17,tun-mtu 1420"
	if ok, err := p.add([]byte(raw)); !ok || err != nil {
		t.Fatalf("push: %t %v", ok, err)
	}
	routes := p.Tunnel.Routes()
	if !p.Tunnel.BlockIPv6 || p.Tunnel.MTU != 1420 || len(routes) != 2 || !routes[0].HasMetric || routes[0].Metric != 101 || routes[1].Metric != 17 {
		t.Fatal("lost block or metric metadata")
	}
	for _, input := range []string{"route-delay", "route-delay 5 30 60", "route-delay -1", "route-metric -1", "route-metric 5,route-metric 5", "dhcp-pre-release unexpected", "register-dns unexpected", "block-ipv6 unexpected", "block-ipv6,block-ipv6", "up secret"} {
		p := pushState{allowed: []string{"AES-256-GCM"}}
		if ok, err := p.add([]byte(pushBase + "," + input)); ok || err != ErrNegotiation {
			t.Fatalf("accepted invalid push: %q", input)
		}
	}
	for _, policy := range []tunnel.PushAction{tunnel.PushIgnore, tunnel.PushReject} {
		p := pushState{allowed: []string{"AES-256-GCM"}, policy: tunnel.PushPolicy{Addresses: policy}}
		if ok, err := p.add([]byte(pushBase + ",block-ipv6")); ok || err != ErrNegotiation {
			t.Fatal("block-ipv6 policy silently ignored")
		}
	}
}
