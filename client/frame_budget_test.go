package client

import (
	"context"
	"testing"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

func TestMinimumDataFrameBudgetIsValidatedBeforeDial(t *testing.T) {
	pki := testkit.NewPKI(t)
	for _, tc := range []struct {
		name        string
		network     string
		maxFrame    int
		tunnelMTU   int
		endpointMTU int
		fixedV1     bool
		valid       bool
	}{
		{"udp_default_short", "udp4", 91, 0, 0, false, false},
		{"tcp_default_short", "tcp4", 91, 0, 0, false, false},
		{"tcp_configured_short", "tcp4", 91, 1200, 0, false, false},
		{"udp_endpoint_short", "udp4", 91, 0, 1200, false, false},
		{"udp_minimum", "udp4", 92, 0, 0, false, true},
		{"tcp_minimum", "tcp4", 92, 0, 0, false, true},
		{"udp_endpoint_minimum", "udp4", 92, 1420, 1200, false, true},
		{"fixed_data_v1_short", "udp4", 91, 0, 0, true, false},
		{"fixed_data_v1_minimum", "udp4", 92, 0, 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Endpoints: []Endpoint{{Host: "127.0.0.1", Network: tc.network, TunnelMTU: tc.endpointMTU}},
				TLS: &TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey,
					RequireServerUsage: true},
				MaxPacketSize: tc.maxFrame, TunnelMTU: tc.tunnelMTU,
				Dialer: testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
					t.Fatal("configuration validation opened a transport")
					return nil, nil
				}),
			}
			if tc.fixedV1 {
				cfg.Endpoints[0].FixedAEAD, cfg.Endpoints[0].FixedAEADDataV1 = "AES-256-GCM", true
				cfg.Endpoints[0].VerifyX509Name.Mode = X509CommonName
				cfg.Endpoints[0].VerifyX509Name.Value = testkit.TestServerName
				cfg.Credentials = &Credentials{Username: "test", Password: "test"}
			}
			c, err := New(cfg)
			if !tc.valid {
				assertCode(t, err, CodeConfig)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
		})
	}
}
