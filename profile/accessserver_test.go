package profile

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestAccessServerImport(t *testing.T) {
	pki := testkit.NewPKI(t)
	section := func(name string, b []byte) string { return "<" + name + ">\n" + string(b) + "\n</" + name + ">\n" }
	material := section("ca", pki.CA) + section("cert", pki.Client.Certificate) + section("key", pki.Client.PrivateKey)
	shape := "cipher AES-256-CBC\nclient\nserver-poll-timeout 4\nnobind\nremote vpn.example.test 1194 udp\nremote vpn.example.test 443 tcp\ndev tun\ndev-type tun\nremote-cert-tls server\ntls-version-min 1.3\nreneg-sec 604800\ntun-mtu 1420\nverb 3\npush-peer-info\n"
	opts := Options{AccessServerName: "OpenVPN Server"}
	for _, login := range []bool{false, true} {
		body := shape + material
		options := opts
		if login {
			body += "auth-user-pass\n"
			options.Credentials = &client.Credentials{Username: "test-user", Password: "test-password"}
		}
		cfg, warn, err := Parse(strings.NewReader(body), options)
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Endpoints) != 2 || cfg.RekeyInterval != 7*24*time.Hour || cfg.TLS.MinVersion != 0x0304 || !cfg.TLS.RequireServerUsage || (cfg.Credentials != nil) != login {
			t.Fatal("profile semantics lost")
		}
		for _, e := range cfg.Endpoints {
			if e.VerifyX509Name.Mode != client.X509CommonName || e.VerifyX509Name.Value != "OpenVPN Server" || e.TunnelMTU != 1420 {
				t.Fatal("identity or MTU lost")
			}
		}
		for _, c := range cfg.DataCiphers {
			if strings.Contains(c, "CBC") {
				t.Fatal("legacy cipher enabled")
			}
		}
		if len(warn) != 3 {
			t.Fatalf("expected legacy cipher, verb and peer info warnings: %v", warn)
		}
		c, err := client.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		report, err := InspectWithOptions(strings.NewReader(body), options)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range report.Entries {
			if entry.Capability == Rejected || entry.Capability == PolicyDisabled {
				t.Fatalf("unexpected capability: %+v", entry)
			}
		}
	}
	tests := []struct {
		name, body string
		opts       Options
		directive  string
		code       Code
	}{
		{"strict", shape + material, Options{}, "cipher", CodeUnsupported},
		{"wrong name", shape + "verify-x509-name other name\n" + material, opts, "verify-x509-name", CodeConflict},
		{"missing role", strings.Replace(shape, "remote-cert-tls server\n", "", 1) + material, opts, "remote-cert-tls", CodeRequired},
		{"CBC offer", shape + "data-ciphers AES-256-CBC\n" + material, opts, "data-ciphers", CodeUnsupported},
		{"fallback", shape + "data-ciphers-fallback AES-256-CBC\n" + material, opts, "data-ciphers-fallback", CodeUnsupported},
		{"other legacy", strings.Replace(shape, "AES-256-CBC", "BF-CBC", 1) + material, opts, "cipher", CodeUnsupported},
		{"long timer", strings.Replace(shape, "604800", "604801", 1) + material, opts, "reneg-sec", CodeValue},
		{"mixed provider", shape + material, Options{AccessServerName: "OpenVPN Server", ExpressVPNManual: true}, "verify-x509-name", CodeConflict},
		{"peer info arguments", strings.Replace(shape, "push-peer-info\n", "push-peer-info extra\n", 1) + material, opts, "push-peer-info", CodeSyntax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Parse(strings.NewReader(tt.body), tt.opts)
			var d *Diagnostic
			if !errors.As(err, &d) || d.Code != tt.code || d.Directive != tt.directive {
				t.Fatalf("expected %s/%s: %v", tt.directive, tt.code, err)
			}
		})
	}
}
