package profile

import (
	"errors"
	"strings"
	"testing"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestAccessServerLockedV2(t *testing.T) {
	pki := testkit.NewPKI(t)
	base := "client\ndev tun\nremote vpn.example.test 1194 udp\nremote-cert-tls server\n<ca>\n" + string(pki.CA) + "\n</ca>\nauth-user-pass\n"
	marker := "setenv CLIENT_CERT 0\n"
	creds := &client.Credentials{Username: "lab-user", Password: "lab-password"}
	opts := Options{AccessServerName: "OpenVPN Server", AllowPasswordOnly: true, Credentials: creds}
	cfg, warn, err := Parse(strings.NewReader(base+marker), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TLS.AllowPasswordOnly || len(cfg.TLS.Certificate) != 0 || !cfg.TLS.RequireServerUsage || len(warn) != 1 {
		t.Fatal("password-only policy lost")
	}
	for _, v := range []struct {
		name, body string
		opts       Options
		code       Code
	}{
		{"no opt-in", base + marker, Options{AccessServerName: "OpenVPN Server", Credentials: creds}, CodeUnsupported},
		{"arbitrary environment", base + "setenv PATH 0\n", opts, CodeUnsupported},
		{"invalid marker", base + "setenv CLIENT_CERT 1\n", opts, CodeUnsupported},
		{"duplicate marker", base + marker + marker, opts, CodeConflict},
		{"missing auth", strings.Replace(base, "auth-user-pass\n", "", 1) + marker, opts, CodeConflict},
		{"conflicting cert", base + marker + "<cert>\n" + string(pki.Client.Certificate) + "\n</cert>\n", opts, CodeConflict},
	} {
		t.Run(v.name, func(t *testing.T) {
			_, _, err := Parse(strings.NewReader(v.body), v.opts)
			var d *Diagnostic
			if !errors.As(err, &d) || d.Code != v.code {
				t.Fatalf("expected %s, got %v", v.code, err)
			}
		})
	}
}
