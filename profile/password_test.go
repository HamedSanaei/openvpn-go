package profile

import (
	"errors"
	"strings"
	"testing"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestPasswordOnlyRequiresOptInTrustAndCredentials(t *testing.T) {
	pki := testkit.NewPKI(t)
	base := "client\ndev tun\nremote vpn.example.test\n"
	ca := "<ca>\n" + string(pki.CA) + "</ca>\n"
	cert := "<cert>\n" + string(pki.Client.Certificate) + "</cert>\n"
	key := "<key>\n" + string(pki.Client.PrivateKey) + "</key>\n"
	creds := &client.Credentials{Username: "test-user", Password: "test-password"}
	for _, tc := range []struct {
		text    string
		opts    Options
		missing string
	}{
		{ca + "auth-user-pass\n", Options{Credentials: creds}, "cert"},
		{ca, Options{AllowPasswordOnly: true, Credentials: creds}, "cert"},
		{"auth-user-pass\n", Options{AllowPasswordOnly: true, Credentials: creds}, "ca"},
		{ca + "auth-user-pass\n", Options{AllowPasswordOnly: true}, "auth-user-pass"},
		{ca + cert + "auth-user-pass\n", Options{AllowPasswordOnly: true, Credentials: creds}, "key"},
		{ca + key + "auth-user-pass\n", Options{AllowPasswordOnly: true, Credentials: creds}, "cert"},
	} {
		_, _, err := Parse(strings.NewReader(base+tc.text), tc.opts)
		var diag *Diagnostic
		if !errors.As(err, &diag) || diag.Code != CodeRequired || diag.Directive != tc.missing {
			t.Fatalf("expected missing %s, got %v", tc.missing, err)
		}
	}
	cfg, _, err := Parse(strings.NewReader(base+ca+"auth-user-pass\n"), Options{AllowPasswordOnly: true, Credentials: creds})
	if err != nil || !cfg.TLS.AllowPasswordOnly || cfg.Credentials == nil || len(cfg.TLS.Certificate) != 0 {
		t.Fatalf("password-only profile = %v", err)
	}
	if _, err := client.New(cfg); err != nil {
		t.Fatal(err)
	}
}
