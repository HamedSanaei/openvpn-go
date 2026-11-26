//go:build linux

package interop_test

import (
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
		name, verify                             string
		keypair, allow, wrongName, wrongPassword bool
		want                                     client.ErrorCode
	}{
		{"password_only", "none", false, true, false, false, ""},
		{"optional_without_certificate", "optional", false, true, false, false, ""},
		{"optional_with_certificate", "optional", true, true, false, false, ""},
		{"required_certificate", "require", true, false, false, false, ""},
		{"wrong_password", "none", false, true, false, true, client.CodeAuthentication},
		{"invalid_server_identity", "none", false, true, true, false, client.CodeCertificate},
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
			text := fmt.Sprintf("client\ndev tun\nremote 127.0.0.1 %d tcp4\nremote-cert-tls server\nverify-x509-name %s name\nauth-user-pass\n", port, name)
			if tc.keypair {
				text += profilePKI(pki)
			} else {
				text += profileSection("ca", pki.CA)
			}
			cfg, _, err := profile.Parse(strings.NewReader(text), profile.Options{
				AllowPasswordOnly: tc.allow,
				Credentials:       &client.Credentials{Username: username, Password: pass},
			})
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
