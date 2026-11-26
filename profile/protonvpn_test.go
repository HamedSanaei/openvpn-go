package profile

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestProtonManualImport(t *testing.T) {
	pki := testkit.NewPKI(t)
	const base = "client\ndev tun\nremote 192.0.2.9 443 tcp4\nremote 192.0.2.9 8443 tcp4\nremote-random\nauth-user-pass\nremote-cert-tls server\n"
	const hints = "setenv CLIENT_CERT 0\nmssfix 0\ntun-mtu 1500\nreneg-sec 0\ncipher AES-256-GCM\n"
	const hooks = "script-security 2\nup /etc/openvpn/update-resolv-conf\ndown /etc/openvpn/update-resolv-conf\n"
	ca := "<ca>\n" + string(pki.CA) + "</ca>\n"
	opts := Options{
		ProtonVPNServerName: testkit.TestServerName, AllowPasswordOnly: true,
		Credentials: &client.Credentials{Username: "fixture", Password: "generated-only"},
	}

	for _, optional := range []string{"", hooks, "block-outside-dns\n"} {
		cfg, warnings, err := Parse(strings.NewReader(base+hints+optional+ca), opts)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.TLS.AllowPasswordOnly || !cfg.TLS.RequireServerUsage || !cfg.RemoteRandom ||
			!cfg.DisableTimedRekey || len(cfg.Endpoints) != 2 || len(warnings) < 3 {
			t.Fatal("import lost an authentication, retry or security setting")
		}
		for _, endpoint := range cfg.Endpoints {
			want := client.X509Name{Mode: client.X509CommonName, Value: testkit.TestServerName}
			if endpoint.Host != "192.0.2.9" || endpoint.VerifyX509Name != want ||
				endpoint.TunnelMTU != 1500 || endpoint.FixedAEAD != "" {
				t.Fatal("import lost the transport settings or independent identity")
			}
		}
	}

	for _, tc := range []struct {
		name, body string
		opts       Options
		code       Code
		directive  string
	}{
		{"strict baseline", base + hints + ca, Options{AllowPasswordOnly: true}, CodeUnsupported, "setenv"},
		{"requires password opt-in", base + hints + ca, Options{ProtonVPNServerName: testkit.TestServerName, Credentials: opts.Credentials}, CodeRequired, "cert"},
		{"requires external credentials", base + hints + ca, Options{ProtonVPNServerName: testkit.TestServerName, AllowPasswordOnly: true}, CodeRequired, "auth-user-pass"},
		{"requires certificate role", strings.Replace(base, "remote-cert-tls server\n", "", 1) + hints + ca, opts, CodeRequired, "remote-cert-tls"},
		{"requires CA", base + hints, opts, CodeRequired, "ca"},
		{"wildcard name", base + hints + ca, Options{ProtonVPNServerName: "*.example.test"}, CodeValue, "verify-x509-name"},
		{"conflicting certificate identity", base + "verify-x509-name other.example.test name\n" + hints + ca, opts, CodeConflict, "verify-x509-name"},
		{"profile cannot use another auth file", strings.Replace(base, "auth-user-pass\n", "auth-user-pass private-auth\n", 1) + hints + ca, opts, CodeUnsupported, "auth-user-pass"},
		{"arbitrary environment", base + "setenv PATH private-entry\n" + ca, opts, CodeUnsupported, "setenv"},
		{"unverified certificate hint", base + "setenv CLIENT_CERT 1\n" + ca, opts, CodeUnsupported, "setenv"},
		{"Windows DNS hint with arguments", base + "block-outside-dns extra\n" + ca, opts, CodeSyntax, "block-outside-dns"},
		{"duplicate hint", base + hints + "mssfix 0\n" + ca, opts, CodeConflict, "mssfix"},
		{"MSS mutation", base + "mssfix 1300\n" + ca, opts, CodeUnsupported, "mssfix"},
		{"legacy negotiation", base + "compat-fixed-aead AES-256-GCM\n" + ca, opts, CodeUnsupported, "compat-fixed-aead"},
		{"weak encryption", base + "cipher AES-256-CBC\n" + ca, opts, CodeUnsupported, "cipher"},
		{"incomplete hook group", base + "script-security 2\nup /etc/openvpn/update-resolv-conf\n" + ca, opts, CodeConflict, "script-security"},
		{"arbitrary hook", base + strings.Replace(hooks, "/etc/openvpn/update-resolv-conf", "/tmp/untrusted", 1) + ca, opts, CodeUnsupported, "up"},
		{"hook arguments", base + strings.Replace(hooks, "/etc/openvpn/update-resolv-conf\n", "/etc/openvpn/update-resolv-conf extra\n", 1) + ca, opts, CodeSyntax, "up"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Parse(strings.NewReader(tc.body), tc.opts)
			var diag *Diagnostic
			if !errors.As(err, &diag) || diag.Code != tc.code || diag.Directive != tc.directive {
				t.Fatalf("unexpected redacted diagnostic: %v", err)
			}
		})
	}
}

func TestProtonHintInspection(t *testing.T) {
	source := "setenv CLIENT_CERT 0\nmssfix 0\nscript-security 2\nup /etc/openvpn/update-resolv-conf\ndown /etc/openvpn/update-resolv-conf\nsetenv PATH private-value\n"
	report, err := InspectWithOptions(strings.NewReader(source), Options{ProtonVPNServerName: testkit.TestServerName})
	if err != nil || len(report.Entries) != 6 {
		t.Fatalf("incorrect capability report: %+v %v", report, err)
	}
	for i, entry := range report.Entries {
		want := Ignored
		if i == 5 {
			want = PolicyDisabled
		}
		if entry.Line != i+1 || entry.Capability != want {
			t.Fatalf("line %d: expected %s, got %+v", i+1, want, entry)
		}
	}
}

func TestProtonVPNNumericRemoteImport(t *testing.T) {
	pki := testkit.NewPKI(t)
	const policy = "client\ndev tun\nproto tcp\nremote-random\nserver-poll-timeout 20\nremote-cert-tls server\nauth-user-pass\nsetenv CLIENT_CERT 0\nmssfix 0\n"
	ca := "<ca>\n" + string(pki.CA) + "</ca>\n"
	remotes := strings.Repeat("remote 192.0.2.1 443\nremote 192.0.2.2 80\nremote 192.0.2.3 8443\n", 21)
	opts := Options{
		ProtonVPNVerifyIP: true, AllowPasswordOnly: true,
		Credentials: &client.Credentials{Username: "fixture", Password: "generated-only"},
	}
	cfg, _, err := Parse(strings.NewReader(policy+remotes+ca), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.RemoteRandom || !cfg.TLS.RequireServerUsage || !cfg.TLS.AllowPasswordOnly || len(cfg.Endpoints) != 63 {
		t.Fatal("import lost remotes or changed the trust policy")
	}
	for i, endpoint := range cfg.Endpoints {
		addresses := [...]string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
		if endpoint.Host != addresses[i%3] || endpoint.ServerName != endpoint.Host ||
			endpoint.VerifyX509Name.Mode != "" || endpoint.ServerPollTimeout != 20*time.Second {
			t.Fatalf("incorrect address or poll policy for candidate %d", i)
		}
	}
	for _, tc := range []struct {
		directive string
		code      Code
	}{
		{"remote unverified.example.test 443\n", CodeValue},
		{"verify-x509-name alternate.example.test name\n", CodeConflict},
	} {
		_, _, err := Parse(strings.NewReader(policy+tc.directive+"remote 192.0.2.1\n"+ca), opts)
		var diag *Diagnostic
		if !errors.As(err, &diag) || diag.Code != tc.code {
			t.Fatalf("expected redacted %s, got %v", tc.code, err)
		}
	}
	opts.ProtonVPNServerName = testkit.TestServerName
	_, _, err = Parse(strings.NewReader(policy+remotes+ca), opts)
	var diag *Diagnostic
	if !errors.As(err, &diag) || diag.Code != CodeConflict || diag.Directive != "verify-x509-name" {
		t.Fatalf("expected conflicting identity policies, got %v", err)
	}
}
