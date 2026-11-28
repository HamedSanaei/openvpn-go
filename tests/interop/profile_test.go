//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/profile"
)

func TestProfilesOpenVPN26(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, binary, pki)
	for _, network := range []string{"udp", "tcp"} {
		for _, mode := range []string{"tls", "tls-auth", "tls-crypt", "v2", "v2-cookie"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				// The UDP fixture uses inline material and a single remote.
				// The TCP fixture resolves files and selects a connection block.
				external := network == "tcp"
				min, max := "1.2", "1.2"
				version := uint16(tls.VersionTLS12)
				if external {
					min, max = "1.3", "1.3"
					version = tls.VersionTLS13
				}
				port := f.start(t, network, mode, true, "--tls-version-min", min, "--tls-version-max", max)
				text := fmt.Sprintf("client\ndev tun\nremote-cert-tls server\ndata-ciphers AES-256-GCM\ntls-version-min %s\ntls-version-max %s\n", min, max)
				var opts profile.Options
				if external {
					body := fmt.Sprintf("proto tcp4-client\nremote 127.0.0.1 1 udp4\nrport %d\nproto tcp4-client\n", port)
					files := map[string][]byte{
						"ca bundle.pem": pki.CA, "cert.pem": pki.Client.Certificate, "key.pem": pki.Client.PrivateKey,
						"credentials": []byte(username + "\r\n" + password + "\r\n"),
					}
					if option, key := profileProtection(f, mode); option != "" {
						files["outer.key"] = key
						body += option + " outer.key\n"
						if mode == "tls-auth" {
							body += "key-direction 1\n"
							text += "auth SHA256\n"
						}
					}
					text += profileSection("connection", []byte(body)) + profileSection("connection", []byte("remote 192.0.2.1\n"))
					text += "ca 'ca bundle.pem'\ncert cert.pem\nkey key.pem\nauth-user-pass credentials\n"
					text += "verify-x509-name 'CN=" + testkit.TestServerName + "' subject\n"
					opts.Root = writeProfileReferences(t, files)
				} else {
					text += fmt.Sprintf("remote 127.0.0.1 %d udp4\n", port)
					text += profilePKI(pki) + profileSection("auth-user-pass", []byte(username+"\n"+password))
					text += "verify-x509-name " + testkit.TestServerName + " name\n"
					if option, key := profileProtection(f, mode); option != "" {
						text += profileSection(option, key)
						if mode == "tls-auth" {
							text += "key-direction 1\nauth SHA256\n"
						}
					}
				}
				cfg, warnings, err := profile.Parse(strings.NewReader(text), opts)
				if err != nil || len(warnings) != 0 {
					t.Fatalf("Parse = %v, warnings %v", err, warnings)
				}
				if external && len(cfg.Endpoints) != 2 {
					t.Fatal("secondary candidate was dropped")
				}
				// The verified certificate exact identity comes from the profile.
				cfg.Endpoints[0].ServerName = "another.example.test"
				cfg.HandshakeTimeout = 8 * time.Second
				if info := connect(t, cfg); info.TLSVersion != version || info.DataCipher != "AES-256-GCM" {
					t.Fatalf("unexpected negotiation: %+v", info)
				}
			})
		}
	}
	t.Run("verification_precedes_credentials", func(t *testing.T) {
		script := []byte("#!/bin/sh\n: > auth-attempted\nexec ./verify-user \"$@\"\n")
		if err := os.WriteFile(filepath.Join(f.dir, "observe-user"), script, 0700); err != nil {
			t.Fatal(err)
		}
		port := f.start(t, "tcp", "tls", true, "--auth-user-pass-verify", "./observe-user", "via-file")
		base := fmt.Sprintf("client\ndev tun\nremote 127.0.0.1 %d tcp4\nremote-cert-tls server\nauth-user-pass\n", port) +
			profilePKI(pki)
		for _, tc := range []struct {
			name, verification, override, password string
			want                                   client.ErrorCode
		}{
			{"wrong_exact_name", "verify-x509-name wrong.example.test name\n", "", password, client.CodeCertificate},
			{"wrong_SAN_with_valid_prefix", "verify-x509-name vpn. name-prefix\n", "wrong.example.test", password, client.CodeCertificate},
			{"wrong_password", "verify-x509-name vpn. name-prefix\n", "", "sensitive-marker-wrong-password", client.CodeAuthentication},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cfg, _, err := profile.Parse(strings.NewReader(base+tc.verification), profile.Options{
					Credentials: &client.Credentials{Username: username, Password: tc.password},
				})
				if err != nil {
					t.Fatal(err)
				}
				if tc.override != "" {
					cfg.Endpoints[0].ServerName = tc.override
				}
				cfg.HandshakeTimeout = 8 * time.Second
				c, err := client.New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				err = c.Connect(t.Context())
				var failure *client.Error
				if !errors.As(err, &failure) || failure.Code != tc.want || strings.Contains(err.Error(), tc.password) {
					t.Fatalf("Connect = %v, want redacted %q", err, tc.want)
				}
				_, err = os.Stat(filepath.Join(f.dir, "auth-attempted"))
				if tc.want == client.CodeCertificate && !errors.Is(err, os.ErrNotExist) {
					t.Fatal("server received an auth attempt after failed verification")
				}
				if tc.want == client.CodeAuthentication && err != nil {
					t.Fatal("password verification was not exercised")
				}
			})
		}
	})
}

func profileProtection(f fixture, mode string) (string, []byte) {
	switch mode {
	case "tls-auth", "tls-crypt":
		return mode, f.key("shared.key")
	case "v2", "v2-cookie":
		return "tls-crypt-v2", f.key("wrapped-client.pem")
	default:
		return "", nil
	}
}

func TestProfileCredentialScopeOpenVPN(t *testing.T) {
	peer := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, peer, pki)
	for _, withAuth := range []bool{false, true} {
		port := f.start(t, "tcp", "tls", withAuth)
		source := fmt.Sprintf("client\ndev tun\nremote 127.0.0.1 %d tcp4\nremote-cert-tls server\n", port) + profilePKI(pki)
		if withAuth {
			source += "auth-user-pass\nauth-nocache\n"
		}
		var invocations atomic.Int32
		cfg, _, err := profile.Parse(strings.NewReader(source), profile.Options{Authentication: client.Authentication{
			Credentials: func(context.Context) (client.Credentials, error) {
				invocations.Add(1)
				return client.Credentials{Username: username, Password: password}, nil
			},
		}})
		if err != nil {
			t.Fatal(err)
		}
		cfg.HandshakeTimeout = 8 * time.Second
		connect(t, cfg)
		var want int32
		if withAuth {
			want = 1 // The fixture validates both supplied credential fields.
		}
		if got := invocations.Load(); got != want {
			t.Fatalf("with auth-user-pass %v: callback invoked %d times, want %d", withAuth, got, want)
		}
	}
}

func profilePKI(pki testkit.PKI) string {
	return profileSection("ca", pki.CA) + profileSection("cert", pki.Client.Certificate) + profileSection("key", pki.Client.PrivateKey)
}

func profileSection(name string, data []byte) string {
	return fmt.Sprintf("<%s>\n%s\n</%s>\n", name, bytes.TrimRight(data, "\n"), name)
}

func writeProfileReferences(t *testing.T, files map[string][]byte) *os.Root {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}
