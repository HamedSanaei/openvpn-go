//go:build linux

package interop_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/profile"
)

func TestOptionalClientIdentityOpenVPN26(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	for _, tc := range []struct {
		name, verify                                     string
		keypair, allow, wrongName, wrongPassword, proton bool
		want                                             client.ErrorCode
	}{
		{"password_only", "none", false, true, false, false, false, ""},
		{"optional_without_certificate", "optional", false, true, false, false, false, ""},
		{"optional_with_certificate", "optional", true, true, false, false, false, ""},
		{"required_certificate", "require", true, false, false, false, false, ""},
		{"wrong_password", "none", false, true, false, true, false, client.CodeAuthentication},
		{"invalid_server_identity", "none", false, true, true, false, false, client.CodeCertificate},
		{"proton_import", "none", false, true, false, false, true, ""},
		{"proton_wrong_password", "none", false, true, false, true, true, client.CodeAuthentication},
		{"proton_wrong_identity", "none", false, true, true, false, true, client.CodeCertificate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFixture(t, binary, pki)
			script := []byte("#!/bin/sh\n: > auth-attempted\nexec ./verify-user \"$@\"\n")
			if err := os.WriteFile(filepath.Join(f.dir, "observe-user"), script, 0700); err != nil {
				t.Fatal(err)
			}
			port := f.start(t, "tcp", "tls", true, "--verify-client-cert", tc.verify,
				"--username-as-common-name", "--auth-user-pass-verify", "./observe-user", "via-file")
			name := testkit.TestServerName
			if tc.wrongName {
				name = "wrong.example.test"
			}
			pass := password
			if tc.wrongPassword {
				pass = "wrong-synthetic-password"
			}
			text := fmt.Sprintf("client\ndev tun\nremote 127.0.0.1 %d tcp4\nremote-cert-tls server\nauth-user-pass\n", port)
			opts := profile.Options{
				AllowPasswordOnly: tc.allow,
				Credentials:       &client.Credentials{Username: username, Password: pass},
			}
			if tc.proton {
				opts.ProtonVPNServerName = name
				text += "setenv CLIENT_CERT 0\nmssfix 0\n"
			} else {
				text += "verify-x509-name " + name + " name\n"
			}
			if tc.keypair {
				text += profilePKI(pki)
			} else {
				text += profileSection("ca", pki.CA)
			}
			cfg, _, err := profile.Parse(strings.NewReader(text), opts)
			if err != nil {
				t.Fatal(err)
			}
			cfg.HandshakeTimeout = 5 * time.Second
			c, err := client.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			err = c.Connect(t.Context())
			if tc.want == "" {
				info, ok := c.ControlInfo()
				if err != nil || !ok || !info.Tunnel.IPv4.IsValid() {
					t.Fatalf("connect = %v, authenticated tunnel = %t", err, ok)
				}
			} else {
				var failure *client.Error
				if !errors.As(err, &failure) || failure.Code != tc.want || strings.Contains(err.Error(), pass) {
					t.Fatalf("expected redacted %q, got %v", tc.want, err)
				}
			}
			_, observed := os.Stat(filepath.Join(f.dir, "auth-attempted"))
			if tc.wrongName && !errors.Is(observed, os.ErrNotExist) || !tc.wrongName && observed != nil {
				t.Fatalf("unexpected credential verifier result: %v", observed)
			}
		})
	}
}

func TestProtonVPNIPIdentityOpenVPN26(t *testing.T) {
	binary := interopPeer(t)
	for _, tc := range []struct {
		name string
		edit func(*x509.Certificate)
		want client.ErrorCode
	}{
		{"matching_ip_san", nil, ""},
		{"missing_ip_san", func(cert *x509.Certificate) { cert.IPAddresses = nil }, client.CodeCertificate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := testkit.NewPKIWithServer(t, tc.edit)
			f := makeFixture(t, binary, pki)
			if err := os.WriteFile(filepath.Join(f.dir, "observe-user"),
				[]byte("#!/bin/sh\n: > auth-attempted\nexec ./verify-user \"$@\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			port := f.start(t, "tcp", "tls", true, "--verify-client-cert", "none",
				"--username-as-common-name", "--auth-user-pass-verify", "./observe-user", "via-file")
			text := fmt.Sprintf("client\ndev tun\nremote 127.0.0.1 %d tcp4\nremote-cert-tls server\nauth-user-pass\nsetenv CLIENT_CERT 0\nserver-poll-timeout 2\n", port)
			cfg, _, err := profile.Parse(strings.NewReader(text+profileSection("ca", pki.CA)), profile.Options{
				AllowPasswordOnly: true, ProtonVPNVerifyIP: true,
				Authentication: client.Authentication{Credentials: func(ctx context.Context) (client.Credentials, error) {
					// The credentials callback occurs after the peer's first response
					// and can outlive the initial server poll deadline.
					timer := time.NewTimer(2100 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-ctx.Done():
						return client.Credentials{}, ctx.Err()
					case <-timer.C:
						return client.Credentials{Username: username, Password: password}, nil
					}
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			c, err := client.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			err = c.Connect(t.Context())
			_, attempted := os.Stat(filepath.Join(f.dir, "auth-attempted"))
			if tc.want == "" {
				if err != nil || attempted != nil {
					t.Fatalf("initial poll deadline ended a verified handshake: %v, verifier %v", err, attempted)
				}
				return
			}
			var failure *client.Error
			if !errors.As(err, &failure) || failure.Code != tc.want || !errors.Is(attempted, os.ErrNotExist) {
				t.Fatalf("missing IP SAN did not stop authentication: %v, verifier %v", err, attempted)
			}
		})
	}
}
