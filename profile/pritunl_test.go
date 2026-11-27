package profile

import (
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestPritunlExportPolicy(t *testing.T) {
	pki := testkit.NewPKI(t)
	base := "# synthetic metadata, not a raw export\nignore-unknown-option data-ciphers\nsetenv UV_ID 0123456789abcdef0123456789abcdef\nsetenv UV_NAME lab-test\nclient\ndev tun\ndev-type tun\nremote vpn.example.test 1194 udp\nnobind\npersist-tun\ncipher AES-256-CBC\ndata-ciphers AES-256-GCM:AES-256-CBC\nauth SHA256\nverb 4\nmute 4\npush-peer-info\nping 10\nping-restart 60\nhand-window 70\nserver-poll-timeout 4\nreneg-sec 2592000\nsndbuf 393216\nrcvbuf 393216\nremote-cert-tls server\nignore-unknown-option block-outside-dns\nblock-outside-dns\n" + inlinePKI(pki)
	opts := Options{PritunlServerName: testkit.TestServerName}
	for _, tc := range []struct{ name, body string }{
		{"AES256", base},
		{"AES256 with an AEAD-only offer", strings.Replace(base, "data-ciphers AES-256-GCM:AES-256-CBC", "data-ciphers AES-256-GCM", 1)},
		{"AES128", strings.ReplaceAll(base, "AES-256", "AES-128")},
		{"ChaCha", strings.ReplaceAll(strings.ReplaceAll(base, "AES-256-GCM:AES-256-CBC", "CHACHA20-POLY1305"), "AES-256-CBC", "CHACHA20-POLY1305")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, warnings, err := Parse(strings.NewReader(tc.body), opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.DataCiphers) != 1 || strings.Contains(cfg.DataCiphers[0], "CBC") || cfg.RekeyInterval != 7*24*time.Hour || !cfg.TLS.RequireServerUsage || cfg.Endpoints[0].VerifyX509Name.Value != testkit.TestServerName || len(warnings) == 0 {
				t.Fatal("incorrect safe import")
			}
			c, err := client.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			rep, err := InspectWithOptions(strings.NewReader(tc.body), opts)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range rep.Entries {
				if e.Capability == Rejected || e.Capability == PolicyDisabled {
					t.Fatalf("unexpected capability: %+v", e)
				}
			}
		})
	}
	for _, body := range []string{
		strings.Replace(base, "ignore-unknown-option data-ciphers", "ignore-unknown-option up", 1),
		strings.Replace(base, "setenv UV_NAME lab-test", "setenv PATH unsafe", 1),
		strings.Replace(base, "data-ciphers AES-256-GCM:AES-256-CBC", "data-ciphers AES-256-CBC", 1),
		strings.Replace(base, "data-ciphers AES-256-GCM:AES-256-CBC", "data-ciphers AES-128-GCM", 1),
		strings.Replace(base, "remote-cert-tls server\n", "", 1),
		base + "verify-x509-name wrong name\n",
		base + "up /tmp/unsafe\n",
		base + "reneg-sec 0\n",
		base + "ignore-unknown-option block-outside-dns\n",
		strings.Replace(base, "ignore-unknown-option block-outside-dns", "ignore-unknown-option script-security", 1),
		strings.Replace(strings.Replace(base, "data-ciphers AES-256-GCM:AES-256-CBC", "data-ciphers AES-256-GCM", 1), "cipher AES-256-CBC", "cipher AES-128-GCM", 1),
	} {
		if _, _, err := Parse(strings.NewReader(body), opts); err == nil {
			t.Fatal("unsafe or contradictory export accepted")
		}
	}
	if _, _, err := Parse(strings.NewReader(base), Options{}); err == nil {
		t.Fatal("policy inferred without opt-in")
	}
}
