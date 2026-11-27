//go:build linux

package interop_test

import (
	"fmt"
	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/profile"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This tests a generated Pritunl-shaped profile against a native Community
// peer, not the Pritunl management/authentication plane.
func TestPritunlShapedCommunityInterop(t *testing.T) {
	fbin := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, fbin, pki)
	shared, err := os.ReadFile(filepath.Join(f.dir, "shared.key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, cipher := range []string{"AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305"} {
			t.Run(network+"/"+cipher, func(t *testing.T) {
				port, echo := startDataPeer(t, f, network, "tls-auth", true, "1.3", cipher)
				legacy, offer := cipher, cipher
				if strings.HasPrefix(cipher, "AES-") {
					legacy = strings.TrimSuffix(cipher, "GCM") + "CBC"
					offer = cipher + ":" + legacy
				}
				body := fmt.Sprintf("ignore-unknown-option data-ciphers\nsetenv UV_ID 0123456789abcdef0123456789abcdef\nsetenv UV_NAME lab-test\nclient\ndev tun\ndev-type tun\nremote 127.0.0.1 %d %s\nnobind\npersist-tun\ncipher %s\ndata-ciphers %s\nauth SHA256\nverb 4\nmute 4\npush-peer-info\nping 10\nping-restart 60\nhand-window 70\nserver-poll-timeout 4\nreneg-sec 2592000\nsndbuf 393216\nrcvbuf 393216\nremote-cert-tls server\nauth-user-pass\nkey-direction 1\n", port, network, legacy, offer) + profilePKI(pki) + profileSection("tls-auth", shared)
				cfg, _, err := profile.Parse(strings.NewReader(body), profile.Options{PritunlServerName: testkit.TestServerName, Credentials: &client.Credentials{Username: username, Password: password}})
				if err != nil {
					t.Fatal(err)
				}
				c, app := connectData(t, cfg)
				info, ok := c.ControlInfo()
				if !ok || info.DataCipher != cipher {
					t.Fatalf("unexpected cipher: %v", info.DataCipher)
				}
				roundtrip(t, app, echo, info.TunnelIP.AsSlice(), []byte("Pritunl-shaped profile"))
				t.Logf("verified bidirectional TUN traffic: %s, %s", network, cipher)
			})
		}
	}
}
