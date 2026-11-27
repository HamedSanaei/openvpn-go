package profile

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestSoftEtherExplicitCompatibility(t *testing.T) {
	pki := testkit.NewPKI(t)
	base := testProfile + "remote-cert-tls server\nverify-x509-name vpn.example.test name\ntls-version-min 1.2\nauth-user-pass\nallow-compression no\n"
	ca := section("ca", pki.CA)
	opts := Options{AllowPasswordOnly: true, Credentials: &client.Credentials{Username: "lab", Password: "synthetic"}}
	for _, cipher := range []string{"AES-128-GCM", "AES-256-GCM"} {
		body := base + "data-ciphers " + cipher + "\ncompat-fixed-aead-v1 " + cipher + "\n" + ca
		cfg, _, err := Parse(strings.NewReader(body), opts)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Endpoints[0].FixedAEADDataV1 || cfg.Endpoints[0].FixedAEAD != cipher {
			t.Fatal("missing explicit policy")
		}
		if _, err = client.New(cfg); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{
			strings.Replace(body, "remote-cert-tls server\n", "", 1),
			strings.Replace(body, "verify-x509-name vpn.example.test name\n", "", 1),
			strings.Replace(body, "compat-fixed-aead-v1 "+cipher, "compat-fixed-aead-v1 AES-128-CBC", 1),
			strings.Replace(body, "dev tun", "dev tap", 1),
			strings.Replace(body, "auth-user-pass\n", "", 1),
			strings.Replace(body, "data-ciphers "+cipher, "data-ciphers AES-128-GCM:AES-256-GCM", 1),
		} {
			if _, _, err := Parse(strings.NewReader(bad), opts); err == nil {
				t.Fatal("unsafe legacy profile accepted")
			}
		}
		if _, _, err := Parse(strings.NewReader(body), Options{Credentials: opts.Credentials}); err == nil {
			t.Fatal("password-only policy inferred")
		}
	}
	for _, stock := range []string{
		"client\ndev tun\nproto udp\nremote vpn.example.test 1194\ncipher AES-128-CBC\nauth SHA1\nauth-user-pass\n",
		"client\ndev tap\nproto udp\nremote vpn.example.test 1194\ncipher AES-128-GCM\nauth-user-pass\n",
	} {
		if _, _, err := Parse(strings.NewReader(stock+ca), opts); err == nil {
			t.Fatal("unsupported stock export accepted")
		}
	}
}

func TestSoftEtherInteractiveOptionsConflict(t *testing.T) {
	pki := testkit.NewPKI(t)
	base := "client\ndev tun\nremote-cert-tls server\nverify-x509-name vpn.example.test name\nauth-user-pass\n" + section("ca", pki.CA)
	const directive = "compat-fixed-aead-v1 AES-256-GCM\n"
	provider := func(context.Context) (client.Credentials, error) {
		t.Fatal("configuration invoked the credential provider")
		return client.Credentials{}, nil
	}
	for _, scope := range []struct{ name, endpoints string }{
		{"top-level", "remote vpn.example.test\n" + directive},
		{"connection-block", "<connection>\nremote vpn.example.test\n" + directive + "</connection>\n"},
	} {
		t.Run(scope.name, func(t *testing.T) {
			text := base + scope.endpoints
			options := Options{AllowPasswordOnly: true, Authentication: client.Authentication{Credentials: provider}}
			cfg, _, err := Parse(strings.NewReader(text), options)
			if err != nil {
				t.Fatal(err)
			}
			c, err := client.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			for _, tc := range []struct {
				name string
				auth client.Authentication
			}{
				{"passive", client.Authentication{AllowPassivePending: true}},
				{"challenge", client.Authentication{Challenge: func(context.Context, client.Challenge) (string, error) { return "", nil }}},
				{"web", client.Authentication{WebAuth: func(context.Context, string) error { return nil }}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					auth := tc.auth
					auth.Credentials = provider
					options.Authentication = auth
					_, _, err := Parse(strings.NewReader(text), options)
					var diagnostic *Diagnostic
					line := 1 + strings.Count(text[:strings.Index(text, directive)], "\n")
					if !errors.As(err, &diagnostic) || *diagnostic != (Diagnostic{CodeConflict, line, "compat-fixed-aead-v1"}) {
						t.Fatalf("unexpected conflict diagnostic: %v", err)
					}
					direct := cfg
					direct.Authentication = auth
					if c, err := client.New(direct); err == nil {
						c.Close()
						t.Fatal("direct configuration bypassed the policy")
					}
					modern := strings.Replace(text, directive, "", 1)
					parsed, _, err := Parse(strings.NewReader(modern), options)
					if err != nil || !parsed.Authentication.Interactive() {
						t.Fatalf("modern interaction lost: %v", err)
					}
				})
			}
		})
	}
}
