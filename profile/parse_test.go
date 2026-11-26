package profile

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

const testProfile = "client\ndev tun\nremote vpn.example.test\n"

func section(name string, body []byte) string {
	return "<" + name + ">\n" + strings.TrimRight(string(body), "\n") + "\n</" + name + ">\n"
}

func inlinePKI(pki testkit.PKI) string {
	return section("ca", pki.CA) + section("cert", pki.Client.Certificate) + section("key", pki.Client.PrivateKey)
}

func staticFixture() []byte {
	var b strings.Builder
	b.WriteString("# synthetic control key fixture\n-----BEGIN OpenVPN Static key V1-----\n")
	for i := range 16 {
		b.WriteString(hex.EncodeToString(bytes.Repeat([]byte{byte(i)}, 16)))
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return []byte(b.String())
}

func wrappedFixture() []byte {
	const wrapped = 32 + 256 + 2
	raw := make([]byte, 256+wrapped)
	binary.BigEndian.PutUint16(raw[len(raw)-2:], wrapped)
	return pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 client key", Bytes: raw})
}

func assertFailure(t *testing.T, source string, opts Options, code Code, directive string, line int) {
	t.Helper()
	cfg, _, err := Parse(strings.NewReader(source), opts)
	var diagnostic *Diagnostic
	if !reflect.DeepEqual(cfg, client.Config{}) || !errors.As(err, &diagnostic) ||
		diagnostic.Code != code || diagnostic.Directive != directive || diagnostic.Line != line {
		t.Fatalf("Parse error = %v, want %s (%s) at line %d", err, code, directive, line)
	}
	if strings.Contains(err.Error(), "sensitive-marker") {
		t.Fatal("profile input leaked in diagnostic")
	}
}

func TestDirectiveRegistry(t *testing.T) {
	pki := testkit.NewPKI(t)
	pkiText := inlinePKI(pki)
	files := fstest.MapFS{
		"ca file.pem": {Data: pki.CA},
		"cert.pem":    {Data: pki.Client.Certificate},
		"key.pem":     {Data: pki.Client.PrivateKey},
		"shared.key":  {Data: staticFixture()},
		"wrapped.pem": {Data: wrappedFixture()},
		"crl.pem":     {Data: pki.CRL(t, time.Now(), false)},
	}
	opts := Options{Resolver: files.Open, Credentials: &client.Credentials{Username: "fixture", Password: "synthetic"}}
	covered := make(map[string]bool)
	for _, tc := range []struct {
		name, good, bad string
		warn            bool
	}{
		{"client", "client", "client yes", false},
		{"tls-client", "tls-client", "tls-client yes", false},
		{"pull", "pull", "pull yes", false},
		{"dev", "dev tun7", "dev tap", false},
		{"dev-type", "dev-type tun", "dev-type tap", false},
		{"remote", "remote vpn2.example.test 8443 tcp6-client", "remote vpn2.example.test 0", false},
		{"connection", "<connection>\nremote vpn.example.test\n</connection>", "<connection>\n</connection>", false},
		{"remote-random", "remote-random", "remote-random yes", false},
		{"proto", "proto tcp4-client", "proto tcp4-server", false},
		{"port", "port 443", "port 65536", false},
		{"rport", "rport 1", "rport +1", false},
		{"ca", "ca ca\\ file.pem", "ca ''", false},
		{"cert", "cert cert.pem", "cert", false},
		{"key", "key key.pem", "key 'C:\\not-allowed.key'", false},
		{"auth-user-pass", "auth-user-pass", "auth-user-pass a b", false},
		{"key-direction", "tls-auth shared.key\nkey-direction 1", "key-direction 2", false},
		{"tls-auth", "tls-auth shared.key 0", "tls-auth shared.key bidirectional", false},
		{"tls-crypt", "tls-crypt shared.key", "tls-crypt shared.key 1", false},
		{"tls-crypt-v2", "tls-crypt-v2 wrapped.pem", "tls-crypt-v2 shared.key", false},
		{"auth", "auth sha256", "auth MD5", false},
		{"data-ciphers", "data-ciphers AES-128-GCM:CHACHA20-POLY1305", "data-ciphers AES-128-GCM:AES-128-GCM", false},
		{"cipher", "cipher AES-256-GCM", "cipher AES-256-CBC", true},
		{"remote-cert-tls", "remote-cert-tls server", "remote-cert-tls client", false},
		{"verify-x509-name", "verify-x509-name 'O=Test VPN, CN=vpn.example.test'", "verify-x509-name vpn.example.test suffix", false},
		{"tls-version-min", "tls-version-min 1.3 or-highest", "tls-version-min 1.1", false},
		{"tls-version-max", "tls-version-max 1.2", "tls-version-max 1.3 or-highest", false},
		{"allow-compression", "allow-compression no", "allow-compression asym", false},
		{"nobind", "nobind", "nobind yes", false},
		{"bind", "bind", "bind\nnobind", false},
		{"local", "local 127.0.0.1", "local not-a-literal", false},
		{"lport", "lport 1195", "lport 0", false},
		{"connect-timeout", "connect-timeout 5", "connect-timeout 121", false},
		{"connect-retry", "connect-retry 1 30", "connect-retry 30 1", false},
		{"connect-retry-max", "connect-retry-max 3", "connect-retry-max 1025", false},
		{"hand-window", "hand-window 90", "hand-window 301", false},
		{"reneg-sec", "reneg-sec 0", "reneg-sec 86401", false},
		{"explicit-exit-notify", "explicit-exit-notify 2", "explicit-exit-notify -1", false},
		{"tun-mtu", "tun-mtu 1400", "tun-mtu 67", false},
		{"auth-nocache", "auth-nocache", "auth-nocache\nauth-user-pass", false},
		{"peer-fingerprint", "peer-fingerprint " + pki.ServerFingerprint(), "peer-fingerprint ff:ff", false},
		{"crl-verify", "crl-verify crl.pem", "crl-verify crl.pem dir", false},
		{"disable-dco", "disable-dco", "disable-dco yes", false},
		{"persist-key", "persist-key", "persist-key yes", true},
		{"persist-tun", "persist-tun", "persist-tun yes", true},
		{"resolv-retry", "resolv-retry infinite", "resolv-retry forever", false},
		{"verb", "verb 3", "verb 12", true},
	} {
		covered[tc.name] = true
		t.Run(tc.name, func(t *testing.T) {
			base, material := testProfile, pkiText
			switch tc.name {
			case "connection":
				base = "client\ndev tun\n"
			case "ca":
				material = section("cert", pki.Client.Certificate) + section("key", pki.Client.PrivateKey)
			case "cert":
				material = section("ca", pki.CA) + section("key", pki.Client.PrivateKey)
			case "key":
				material = section("ca", pki.CA) + section("cert", pki.Client.Certificate)
			}
			cfg, warnings, err := Parse(strings.NewReader(base+tc.good+"\n"+material), opts)
			if err != nil {
				t.Fatal(err)
			}
			if tc.warn {
				want := Diagnostic{CodeIgnored, 4, tc.name}
				if !reflect.DeepEqual(warnings, []Diagnostic{want}) {
					t.Fatalf("warnings = %v, want %v", warnings, want)
				}
			} else if len(warnings) != 0 {
				t.Fatalf("unexpected warnings %v", warnings)
			}
			if _, err := client.New(cfg); err != nil {
				t.Fatalf("client rejected parsed configuration: %v", err)
			}
			if _, _, err := Parse(strings.NewReader(base+tc.bad+"\n"+material), opts); err == nil {
				t.Fatal("malformed form accepted")
			}
		})
	}
	for name := range directives {
		if !covered[name] {
			t.Errorf("directive %s needs valid and invalid fixtures", name)
		}
	}
}

func TestProfileTrustAndCredentialCallbacks(t *testing.T) {
	pki, rotating := testkit.NewPKI(t), testkit.NewPKI(t)
	certificate := section("ca", pki.CA) + section("cert", pki.Client.Certificate)
	pins := section("peer-fingerprint", []byte(pki.ServerFingerprint()+"\n"+rotating.ServerFingerprint()))
	base := testProfile + certificate + pins + section("crl-verify", pki.CRL(t, time.Now(), false))
	user := func(context.Context) (client.Credentials, error) {
		return client.Credentials{Username: "test-user", Password: "test-password"}, nil
	}
	raw, _ := pem.Decode(pki.Client.PrivateKey)
	key, err := x509.ParsePKCS8PrivateKey(raw.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Identity: KeyIdentity{Signer: key.(crypto.Signer)},
		Authentication: client.Authentication{Credentials: user}}
	cfg, warnings, err := Parse(strings.NewReader(base+"auth-user-pass\nauth-nocache\n"), opts)
	if err != nil || len(warnings) != 0 || cfg.Credentials != nil ||
		cfg.Authentication.Credentials == nil || cfg.TLS.Signer == nil || len(cfg.TLS.ServerFingerprints) != 2 {
		t.Fatalf("policy profile failed: %v, warnings %v", err, warnings)
	}
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	for _, extra := range []string{"peer-fingerprint " + pki.ServerFingerprint() + "\n", "crl-verify ../outside.crl\n",
		section("key", pki.Client.PrivateKey), "auth-user-pass private-file\nauth-nocache\n", "up arbitrary-hook\n"} {
		if _, _, err := Parse(strings.NewReader(base+extra), opts); err == nil {
			t.Fatal("rejected policy variant was accepted")
		}
	}
}

func TestRemotePrecedence(t *testing.T) {
	pki := inlinePKI(testkit.NewPKI(t))
	for _, tc := range []struct {
		name, text string
		want       []client.Endpoint
		random     bool
	}{
		{"defaults", "remote 2001:db8::2\n", []client.Endpoint{
			{Host: "2001:db8::2", Network: "udp", Port: 1194, ServerName: "2001:db8::2"},
		}, false},
		{"flat", "proto udp6\nremote one.example.test.\nremote 192.0.2.1 443 tcp4\nremote 2001:db8::1 1195 udp6\nrport 8443\nproto tcp-client\nremote-random\n", []client.Endpoint{
			{Host: "one.example.test.", Port: 8443, Network: "tcp", ServerName: "one.example.test"},
			{Host: "192.0.2.1", Port: 443, Network: "tcp4", ServerName: "192.0.2.1"},
			{Host: "2001:db8::1", Port: 1195, Network: "udp6", ServerName: "2001:db8::1"},
		}, true},
		{"blocks", "proto udp4\nport 1111\n<connection>\nremote 192.0.2.1\n</connection>\n" +
			"proto tcp6-client\nrport 2222\n<connection>\nremote 2001:db8::1\n</connection>\n" +
			"<connection>\nproto udp4\nremote 2001:db8::2 3333 udp6\nport 4444\nproto tcp6\n</connection>\nport 5555\n", []client.Endpoint{
			{Host: "192.0.2.1", Port: 1111, Network: "udp4", ServerName: "192.0.2.1"},
			{Host: "2001:db8::1", Port: 2222, Network: "tcp6", ServerName: "2001:db8::1"},
			{Host: "2001:db8::2", Port: 4444, Network: "tcp6", ServerName: "2001:db8::2"},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := Parse(strings.NewReader("client\ndev tun\n"+tc.text+pki), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.Endpoints, tc.want) || cfg.RemoteRandom != tc.random {
				t.Fatalf("incorrect effective endpoints: %+v", cfg.Endpoints)
			}
		})
	}
}

func TestClientDirectiveSyntax(t *testing.T) {
	source := "\ufeff; standalone TLS client\n--tls-client\npull\n\tdev \"tun\" ; inline comment\n" +
		"remote '192.0.2.10' 443 tcp4-client # TCP candidate\n" + inlinePKI(testkit.NewPKI(t))
	cfg, _, err := Parse(strings.NewReader(strings.TrimSuffix(source, "\n")), Options{})
	if err != nil || len(cfg.Endpoints) != 1 || cfg.Endpoints[0].Network != "tcp4" {
		t.Fatalf("failed to parse quoted profile: %v", err)
	}
}

func TestPerConnectionProtectionAndTLS(t *testing.T) {
	pki := inlinePKI(testkit.NewPKI(t))
	source := "client\ndev tun\n" + section("tls-auth", staticFixture()) + "key-direction 1\nauth SHA384\n" +
		"<connection>\nremote first.example.test\n</connection>\n" +
		"<connection>\nremote second.example.test 443 tcp4\n" + section("tls-crypt", staticFixture()) + "</connection>\n" +
		"<connection>\nremote third.example.test\n" + section("tls-crypt-v2", wrappedFixture()) + "</connection>\n" +
		"key-direction 0\n<connection>\nremote fourth.example.test\n</connection>\n" +
		"remote-cert-tls server\nverify-x509-name prefix name-prefix\ntls-version-min 1.3\ntls-version-max 1.3\n" +
		"data-ciphers CHACHA20-POLY1305:AES-128-GCM\n" + pki
	cfg, _, err := Parse(strings.NewReader(source), Options{})
	if err != nil {
		t.Fatal(err)
	}
	controls := cfg.EndpointControls
	if len(controls) != 4 || controls[0].Mode != client.ControlTLSAuth || controls[0].Direction != client.KeyDirection1 ||
		controls[0].Digest != "SHA384" || controls[1].Mode != client.ControlTLSCrypt || controls[1].Direction != client.KeyBidirectional ||
		controls[2].Mode != client.ControlTLSCryptV2 || controls[3].Mode != client.ControlTLSAuth ||
		controls[3].Direction != client.KeyDirection0 {
		t.Fatal("incorrect effective control protection")
	}
	if cfg.TLS.MinVersion != tls.VersionTLS13 || cfg.TLS.MaxVersion != tls.VersionTLS13 || !cfg.TLS.RequireServerUsage ||
		!reflect.DeepEqual(cfg.DataCiphers, []string{"CHACHA20-POLY1305", "AES-128-GCM"}) {
		t.Fatal("incorrect TLS settings")
	}
	for _, e := range cfg.Endpoints {
		if e.VerifyX509Name != (client.X509Name{Mode: client.X509NamePrefix, Value: "prefix"}) {
			t.Fatal("missing endpoint identity policy")
		}
	}
	if _, err := client.New(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestMaterialSources(t *testing.T) {
	pki := testkit.NewPKI(t)
	rootDir := t.TempDir()
	files := map[string][]byte{
		"certs/ca bundle.pem": pki.CA, "certs/cert.pem": pki.Client.Certificate,
		"certs/key.pem": pki.Client.PrivateKey, "login": []byte(" name #1 \r\n pw;2 \r\n"),
	}
	if err := os.Mkdir(filepath.Join(rootDir, "certs"), 0700); err != nil {
		t.Fatal(err)
	}
	virtual := make(fstest.MapFS)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(rootDir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		virtual[name] = &fstest.MapFile{Data: data}
	}
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	external := "ca './certs/ca bundle.pem'\ncert \"certs\\\\cert.pem\" ; comment\nkey certs/key.pem\nauth-user-pass login\n"
	user := client.Credentials{Username: " name #1 ", Password: " pw;2 "}
	for _, tc := range []struct {
		text string
		opts Options
	}{
		{external, Options{Root: root}},
		{external, Options{Resolver: virtual.Open}},
		{inlinePKI(pki) + section("auth-user-pass", files["login"]), Options{}},
		{inlinePKI(pki) + "auth-user-pass\n", Options{Credentials: &user}},
	} {
		source := "\ufeff# generated fixture\r\n" + strings.ReplaceAll(testProfile, "\n", "\r\n") + tc.text
		cfg, warnings, err := Parse(strings.NewReader(source), tc.opts)
		if err != nil || len(warnings) != 0 {
			t.Fatalf("Parse = %v, warnings %v", err, warnings)
		}
		if !bytes.Equal(cfg.TLS.CA, pki.CA) || !bytes.Equal(cfg.TLS.Certificate, pki.Client.Certificate) ||
			!bytes.Equal(cfg.TLS.PrivateKey, pki.Client.PrivateKey) || cfg.Credentials == nil || *cfg.Credentials != user {
			t.Fatal("incorrect loaded material")
		}
	}
}

func TestInvalidProfilesAreRedacted(t *testing.T) {
	pki := testkit.NewPKI(t)
	mat := inlinePKI(pki)
	assertFailure(t, "tls-client\ndev tun\nremote vpn.example.test\n"+mat, Options{}, CodeRequired, "client", 0)
	assertFailure(t, "client\nremote vpn.example.test\n"+mat, Options{}, CodeRequired, "dev", 0)
	assertFailure(t, "client\ndev tun\n"+mat, Options{}, CodeRequired, "remote", 0)
	assertFailure(t, testProfile, Options{}, CodeRequired, "ca", 0)
	assertFailure(t, testProfile+"auth-user-pass\n"+mat, Options{}, CodeRequired, "auth-user-pass", 4)
	assertFailure(t, testProfile+"auth-user-pass\n"+mat, Options{Credentials: &client.Credentials{Password: "sensitive-marker"}}, CodeMaterial, "auth-user-pass", 4)
	for _, tc := range []struct {
		text, name string
		code       Code
		line       int
	}{
		{"server 10.5.0.0 255.255.255.0\n", "server", CodeUnsupported, 4},
		{"secret sensitive-marker\n", "secret", CodeUnsupported, 4},
		{"<secret>\nsensitive-marker\n</secret>\n", "secret", CodeUnsupported, 4},
		{"script-security 2\n", "script-security", CodeUnsupported, 4},
		{"up sensitive-marker\n", "up", CodeUnsupported, 4},
		{"tls-verify sensitive-marker\n", "tls-verify", CodeUnsupported, 4},
		{"remote-cert-ku 80\n", "remote-cert-ku", CodeUnsupported, 4},
		{"ignore-unknown-option sensitive-marker\n", "ignore-unknown-option", CodeUnsupported, 4},
		{"sensitive-marker private\n", "", CodeUnsupported, 4},
		{"compress stub-v2\n", "compress", CodeUnsupported, 4},
		{"comp-lzo no\n", "comp-lzo", CodeUnsupported, 4},
		{"data-ciphers AES-128-GCM:AES-256-CBC\n", "data-ciphers", CodeUnsupported, 4},
		{"data-ciphers AES-128-GCM:\n", "data-ciphers", CodeUnsupported, 4},
		{"data-ciphers-fallback AES-128-GCM\n", "data-ciphers-fallback", CodeUnsupported, 4},
		{"tls-version-min 1.3\ntls-version-max 1.2\n", "tls-version-max", CodeConflict, 5},
		{"verify-x509-name '' name\n", "verify-x509-name", CodeValue, 4},
		{"verify-x509-name 'CN=sensitive-marker+OU=ambiguous'\n", "verify-x509-name", CodeValue, 4},
		{"verify-x509-name first name\nverify-x509-name second name\n", "verify-x509-name", CodeConflict, 5},
		{"remote 'sensitive-marker\n", "remote", CodeSyntax, 4},
		{"remote vpn.example.test:443\n", "remote", CodeValue, 4},
		{"remote 192.0.2.1 1194 udp6\n", "remote", CodeValue, 4},
		{"remote vpn.example.test 1194 udp trailing\n", "remote", CodeSyntax, 4},
		{"</connection>\n", "connection", CodeSyntax, 4},
		{"<connection>\nremote another.example.test\n</connection>\n", "connection", CodeConflict, 4},
		{"<key>\n<sensitive-marker>\n</key>\n", "key", CodeSyntax, 5},
		{"<ca>\nsensitive-marker\n</cert>\n", "ca", CodeSyntax, 6},
		{"<key>\nsensitive-marker\n", "key", CodeSyntax, 4},
		{"tls-auth shared.key\ntls-crypt shared.key\n", "tls-crypt", CodeConflict, 5},
		{"key-direction 0\n", "key-direction", CodeConflict, 4},
		{"key-direction 1\ntls-auth shared.key 0\n", "tls-auth", CodeConflict, 5},
		{"<auth-user-pass>\nsensitive-marker\n</auth-user-pass>\n", "auth-user-pass", CodeMaterial, 4},
		{"<auth-user-pass>\n\n</auth-user-pass>\n", "auth-user-pass", CodeMaterial, 4},
		{"<auth-user-pass>\nuser\npass\nsensitive-marker\n</auth-user-pass>\n", "auth-user-pass", CodeMaterial, 4},
		{section("tls-crypt", []byte("sensitive-marker")), "tls-crypt", CodeMaterial, 4},
	} {
		t.Run(fmt.Sprintf("%s/%s", tc.name, tc.code), func(t *testing.T) {
			source := testProfile + tc.text + mat
			if tc.text == "<key>\nsensitive-marker\n" {
				source = testProfile + tc.text
			}
			assertFailure(t, source, Options{}, tc.code, tc.name, tc.line)
		})
	}
	assertFailure(t, testProfile+section("ca", append([]byte("-----BEGIN CERTIFICATE-----\nbad\n"), pki.CA...))+
		section("cert", pki.Client.Certificate)+section("key", pki.Client.PrivateKey), Options{}, CodeMaterial, "ca", 4)
	for _, invalid := range [][]byte{
		append([]byte(" "), pki.CA...),
		bytes.Join([][]byte{pki.CA, []byte("\t"), pki.CA}, nil),
	} {
		assertFailure(t, testProfile+section("ca", invalid)+section("cert", pki.Client.Certificate)+
			section("key", pki.Client.PrivateKey), Options{}, CodeMaterial, "ca", 4)
	}
	wrong := testkit.NewPKI(t)
	assertFailure(t, testProfile+section("key", wrong.Client.PrivateKey)+section("ca", pki.CA)+
		section("cert", pki.Client.Certificate), Options{}, CodeMaterial, "key", 4)

	for _, tc := range []struct {
		text, directive string
		code            Code
		line            int
	}{
		{"<connection>\n<connection>\n", "connection", CodeScope, 4},
		{"<connection>\nremote vpn.example.test\n", "connection", CodeSyntax, 3},
		{"<connection>\n</connection>\n", "remote", CodeRequired, 3},
		{"<connection>\nremote vpn.example.test\nremote second.example.test\n</connection>\n", "remote", CodeConflict, 5},
		{"<connection>\n<ca>\n", "ca", CodeScope, 4},
		{"<connection>\nremote vpn.example.test\n</connection>\nremote second.example.test\n", "remote", CodeConflict, 6},
	} {
		assertFailure(t, "client\ndev tun\n"+tc.text, Options{}, tc.code, tc.directive, tc.line)
	}
}

func TestFileConfinement(t *testing.T) {
	pki := inlinePKI(testkit.NewPKI(t))
	called := false
	resolver := func(string) (file fs.File, err error) {
		called = true
		return nil, errors.New("sensitive-marker")
	}
	for _, name := range []string{
		"../sensitive-marker", "nested/../sensitive-marker", "/sensitive-marker",
		"C:/sensitive-marker", "C:sensitive-marker", "\\\\server\\share",
		"\\\\?\\sensitive-marker", "a.key:stream", "NUL.txt", "com¹.txt", "AUX .txt", "nested/.. /file",
	} {
		assertFailure(t, testProfile+"tls-auth '"+name+"'\n"+pki, Options{Resolver: resolver}, CodeFile, "tls-auth", 4)
	}
	if called {
		t.Fatal("unsafe paths reached resolver")
	}
	assertFailure(t, testProfile+"tls-auth nested/sensitive-marker\n"+pki, Options{}, CodeFile, "tls-auth", 4)
	assertFailure(t, testProfile+"tls-auth nested/sensitive-marker\n"+pki, Options{Resolver: resolver}, CodeFile, "tls-auth", 4)
	if !called {
		t.Fatal("valid relative path did not reach resolver")
	}

	dir := t.TempDir()
	authorized := filepath.Join(dir, "authorized")
	if err := os.Mkdir(authorized, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(authorized)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	for _, name := range []string{"missing", "folder"} {
		if name == "folder" {
			if err := os.Mkdir(filepath.Join(authorized, name), 0700); err != nil {
				t.Fatal(err)
			}
		}
		assertFailure(t, testProfile+"tls-auth "+name+"\n"+pki, Options{Root: root}, CodeFile, "tls-auth", 4)
	}
	if err := os.WriteFile(filepath.Join(dir, "outside"), staticFixture(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside", filepath.Join(authorized, "escape")); err != nil {
		t.Skip("symlink creation unavailable")
	}
	assertFailure(t, testProfile+"tls-auth escape\n"+pki, Options{Root: root}, CodeFile, "tls-auth", 4)
	if err := os.WriteFile(filepath.Join(authorized, "shared.key"), staticFixture(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("shared.key", filepath.Join(authorized, "local")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Parse(strings.NewReader(testProfile+"tls-auth local\n"+pki), Options{Root: root}); err != nil {
		t.Fatal(err)
	}
}

func TestLimits(t *testing.T) {
	pki := testkit.NewPKI(t)
	base := testProfile + inlinePKI(pki)
	comments := strings.Repeat("#"+strings.Repeat(" ", maxLine-2)+"\n", 16)
	profileAtLimit := base + comments[:maxProfile-len(base)]
	if _, _, err := Parse(strings.NewReader(profileAtLimit), Options{}); err != nil {
		t.Fatal(err)
	}
	assertFailure(t, profileAtLimit+" ", Options{}, CodeLimit, "", 0)
	if _, _, err := Parse(strings.NewReader(base+"#"+strings.Repeat("x", maxLine-1)+"\r\n"), Options{}); err != nil {
		t.Fatal(err)
	}
	assertFailure(t, testProfile+"#"+strings.Repeat("x", maxLine)+"\n"+inlinePKI(pki), Options{}, CodeLimit, "", 4)
	remotes := strings.Repeat("remote 192.0.2.1\n", client.MaxEndpoints-1)
	if cfg, _, err := Parse(strings.NewReader(remotes+base), Options{}); err != nil || len(cfg.Endpoints) != client.MaxEndpoints {
		t.Fatalf("max endpoints rejected: %v", err)
	}
	assertFailure(t, remotes+"remote 192.0.2.2\n"+base, Options{}, CodeLimit, "remote", client.MaxEndpoints+3)

	files := fstest.MapFS{
		"ca":   {Data: append(bytes.Clone(pki.CA), bytes.Repeat([]byte{' '}, maxFileBytes-len(pki.CA)-len(pki.Client.Certificate)-len(pki.Client.PrivateKey))...)},
		"cert": {Data: pki.Client.Certificate}, "key": {Data: pki.Client.PrivateKey},
	}
	source := testProfile + "ca ca\ncert cert\nkey key\n"
	if _, _, err := Parse(strings.NewReader(source), Options{Resolver: files.Open}); err != nil {
		t.Fatal(err)
	}
	files["ca"].Data = append(files["ca"].Data, ' ')
	assertFailure(t, source, Options{Resolver: files.Open}, CodeLimit, "key", 6)
	reader := bytes.NewReader(bytes.Repeat([]byte{'x'}, maxFileBytes+2))
	tracked := &growingFile{Reader: reader}
	assertFailure(t, source, Options{Resolver: func(string) (fs.File, error) {
		file, err := (fstest.MapFS{"meta": {}}).Open("meta")
		tracked.File = file
		return tracked, err
	}}, CodeLimit, "ca", 4)
	if reader.Len() != 1 || !tracked.closed {
		t.Fatal("growing file exceeded its byte limit or was left open")
	}
	padded := bytes.NewReader(bytes.Repeat([]byte{'x'}, maxProfile+2))
	_, _, err := Parse(padded, Options{})
	if err == nil || padded.Len() != 1 {
		t.Fatalf("profile reader exceeded its byte limit: %v", err)
	}
	_, _, err = Parse(io.MultiReader(strings.NewReader(testProfile), failingReader{}), Options{})
	if err == nil || strings.Contains(err.Error(), "sensitive-marker") {
		t.Fatalf("profile read failure was not redacted: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("sensitive-marker") }

type growingFile struct {
	fs.File
	Reader io.Reader
	closed bool
}

func (f *growingFile) Read(p []byte) (int, error) { return f.Reader.Read(p) }

func (f *growingFile) Close() error {
	f.closed = true
	return f.File.Close()
}

func FuzzProfile(f *testing.F) {
	pki := inlinePKI(testkit.NewPKI(f))
	for _, source := range []string{
		"", testProfile + pki, "\ufeff" + testProfile + pki + section("auth-user-pass", []byte("fixture\npass")),
		"client\ndev tun\n<connection>\nremote 2001:db8::1 443 tcp6\n</connection>\n" + pki,
		testProfile + "ca ../../../outside", "<connection>\n<connection>", testProfile + "<key>\n",
		testProfile + "remote \"unterminated", testProfile + "data-ciphers AES-256-CBC",
		testProfile + section("tls-crypt-v2", wrappedFixture()) + pki,
	} {
		f.Add([]byte(source))
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		cfg, _, err := Parse(bytes.NewReader(source), Options{})
		if err != nil {
			var diagnostic *Diagnostic
			if !reflect.DeepEqual(cfg, client.Config{}) || !errors.As(err, &diagnostic) {
				t.Fatal("parse failure returned partial or unclassified state")
			}
			return
		}
		if _, err := client.New(cfg); err != nil {
			t.Fatalf("client rejected parsed configuration: %v", err)
		}
	})
}
