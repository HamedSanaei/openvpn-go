package profile

import (
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestPritunlVerifiedExportPolicy(t *testing.T) {
	pki := inlinePKI(testkit.NewPKI(t))
	body := testProfile + "ignore-unknown-option data-ciphers\nsetenv UV_ID synthetic-id\nsetenv UV_NAME synthetic-name\nremote-cert-tls server\nkey-direction 1\n" +
		"cipher AES-256-CBC\ndata-ciphers AES-256-GCM:AES-256-CBC\nauth SHA256\nmute 4\npush-peer-info\nping 10\nping-restart 60\nhand-window 70\nserver-poll-timeout 4\nreneg-sec 2592000\nsndbuf 393216\nrcvbuf 393216\n"
	opts := Options{PritunlServerName: "vpn.example.test"}
	cfg, warnings, err := Parse(strings.NewReader(body+pki+section("tls-auth", staticFixture())), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DataCiphers) != 1 || cfg.DataCiphers[0] != "AES-256-GCM" || cfg.RekeyInterval != 7*24*time.Hour || cfg.DisableTimedRekey ||
		cfg.Endpoints[0].VerifyX509Name != (client.X509Name{Mode: client.X509CommonName, Value: "vpn.example.test"}) || cfg.Control.Mode != client.ControlTLSAuth {
		t.Fatal("unexpected import policy")
	}
	if len(warnings) < 10 {
		t.Fatal("compatibility changes were not reported")
	}
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, _, err = Parse(strings.NewReader(body+pki+section("tls-auth", staticFixture())), Options{}); err == nil {
		t.Fatal("strict import accepted vendor directives")
	}
	for _, bad := range []string{
		strings.Replace(body, "ignore-unknown-option data-ciphers", "ignore-unknown-option tls-verify", 1),
		strings.Replace(body, "setenv UV_ID", "setenv PATH", 1),
		strings.Replace(body, "data-ciphers AES-256-GCM:AES-256-CBC", "data-ciphers AES-256-CBC", 1),
		strings.Replace(body, "data-ciphers AES-256-GCM:AES-256-CBC", "data-ciphers AES-128-GCM:AES-128-CBC", 1),
		strings.Replace(body, "remote-cert-tls server\n", "", 1),
		body + "verify-x509-name incorrect.invalid name\n",
		body + "data-ciphers AES-256-GCM\n",
		body + "setenv UV_ID another\n",
		body + "compat-fixed-aead-v1 AES-256-GCM\n",
		strings.Replace(body, "reneg-sec 2592000", "reneg-sec 2592001", 1),
	} {
		if _, _, err = Parse(strings.NewReader(bad+pki+section("tls-auth", staticFixture())), opts); err == nil {
			t.Fatal("invalid vendor profile accepted")
		}
	}
	for _, badOpts := range []Options{{PritunlServerName: opts.PritunlServerName, AccessServerName: "other"}, {PritunlServerName: opts.PritunlServerName, AllowPasswordOnly: true}} {
		if _, _, err = Parse(strings.NewReader(body+pki+section("tls-auth", staticFixture())), badOpts); err == nil {
			t.Fatal("conflicting policy accepted")
		}
	}
	report, err := InspectWithOptions(strings.NewReader(body+pki+section("tls-auth", staticFixture())), opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range report.Entries {
		if entry.Capability == Rejected || entry.Capability == PolicyDisabled {
			t.Fatalf("inspection unexpectedly rejected %s", entry.Directive)
		}
	}
}
