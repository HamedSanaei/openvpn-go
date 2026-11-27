package profile

import (
	"errors"
	"strings"
	"testing"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestExpressVPNManualImport(t *testing.T) {
	pki := testkit.NewPKI(t)
	opts := Options{
		ExpressVPNManual: true,
		Credentials:      &client.Credentials{Username: "example-user", Password: "example-password"},
	}
	const shape = "tls-client\npull\ndev tun\nremote vpn.example.test 1194\n" +
		"ns-cert-type server\nverify-x509-name test-server- name-prefix\nauth-user-pass\n" +
		"fragment 1300\ncomp-lzo no\nmssfix 1200\nfast-io\nroute-method exe\nroute-delay 2\n" +
		"sndbuf 524288\nrcvbuf 524288\ncipher AES-256-GCM\nauth SHA512\nkey-direction 1\n"
	section := func(name, value string) string {
		return "<" + name + ">\n" + value + "\n</" + name + ">\n"
	}
	material := section("ca", string(pki.CA)) + section("cert", string(pki.Client.Certificate)) +
		section("key", string(pki.Client.PrivateKey)) + section("tls-auth",
		"-----BEGIN OpenVPN Static key V1-----\n"+strings.Repeat(strings.Repeat("12", 16)+"\n", 16)+"-----END OpenVPN Static key V1-----")
	cfg, warnings, err := Parse(strings.NewReader(shape+material), opts)
	if err != nil {
		t.Fatal(err)
	}
	end := cfg.Endpoints[0]
	if end.ExpressVPNFragmentSize != 1300 || end.Network != "udp" || end.VerifyX509Name.Mode != client.X509CommonNamePrefix ||
		!cfg.TLS.RequireServerUsage || cfg.TLS.AllowPasswordOnly || cfg.Control.Mode != client.ControlTLSAuth ||
		cfg.Control.Direction != client.KeyDirection1 || cfg.Control.Digest != "SHA512" || cfg.Credentials == nil {
		t.Fatal("ExpressVPN import lost transport, peer verification or authentication settings")
	}
	if len(warnings) != 7 {
		t.Fatalf("expected seven advisory warnings, got %v", warnings)
	}
	report, err := InspectWithOptions(strings.NewReader(shape+material), opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range report.Entries {
		if entry.Capability == Rejected || entry.Capability == PolicyDisabled {
			t.Fatalf("rejected a recognized ExpressVPN directive: %+v", entry)
		}
	}
	tests := []struct {
		name, from, to, directive string
		code                      Code
		disable                   bool
	}{
		{"strict", "", "", "ns-cert-type", CodeUnsupported, true},
		{"compression yes", "comp-lzo no", "comp-lzo yes", "comp-lzo", CodeUnsupported, false},
		{"compression adaptive", "comp-lzo no", "comp-lzo adaptive", "comp-lzo", CodeUnsupported, false},
		{"fragment limit", "fragment 1300", "fragment 65508", "fragment", CodeValue, false},
		{"missing fragment", "fragment 1300\n", "", "fragment", CodeRequired, false},
		{"missing name", "verify-x509-name test-server- name-prefix\n", "", "verify-x509-name", CodeRequired, false},
		{"missing role", "ns-cert-type server\n", "", "remote-cert-tls", CodeRequired, false},
		{"file credentials", "auth-user-pass\n", "auth-user-pass secret.txt\n", "auth-user-pass", CodeUnsupported, false},
		{"route hook", "route-method exe", "route-up /tmp/test", "route-up", CodeUnsupported, false},
		{"tcp", "1194\n", "1194 tcp\n", "remote", CodeValue, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := opts
			options.ExpressVPNManual = !tt.disable
			text := shape
			if tt.from != "" {
				text = strings.Replace(text, tt.from, tt.to, 1)
			}
			_, _, err := Parse(strings.NewReader(text+material), options)
			var diagnostic *Diagnostic
			if !errors.As(err, &diagnostic) || diagnostic.Code != tt.code || diagnostic.Directive != tt.directive {
				t.Fatalf("expected %s for %s, got %v", tt.code, tt.directive, err)
			}
		})
	}
}
