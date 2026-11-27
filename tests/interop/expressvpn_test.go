//go:build linux

package interop_test

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/profile"
)

func TestExpressVPNManualOpenVPN(t *testing.T) {
	binary := interopPeer(t)
	version, err := exec.CommandContext(t.Context(), binary, "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	firstLine, _, _ := bytes.Cut(version, []byte{'\n'})
	if !bytes.Contains(firstLine, []byte("[LZO]")) && !bytes.Contains(firstLine, []byte("[LZ4]")) {
		t.Skip("the reference peer was built without compression framing")
	}
	pki := testkit.NewPKIWithServer(t, func(cert *x509.Certificate) {
		cert.DNSNames, cert.IPAddresses = nil, nil
	})
	f := makeFixture(t, binary, pki)
	port, echo := startDataPeer(t, f, "udp", "tls-auth", true, "1.3", "AES-256-GCM",
		"--auth", "SHA512", "--fragment", "1300", "--allow-compression", "asym", "--comp-lzo", "no",
		"--push", "comp-lzo no")
	text := fmt.Sprintf("tls-client\npull\ndev tun\nremote 127.0.0.1 %d\n"+
		"ns-cert-type server\nverify-x509-name vpn.example. name-prefix\nauth-user-pass\n"+
		"comp-lzo no\nfragment 1300\ncipher AES-256-GCM\nauth SHA512\nkey-direction 1\n", port)
	cfg, _, err := profile.Parse(strings.NewReader(text+profilePKI(pki)+profileSection("tls-auth", f.key("shared.key"))),
		profile.Options{ExpressVPNManual: true, Credentials: &client.Credentials{Username: username, Password: password}})
	if err != nil {
		t.Fatal(err)
	}
	cfg.RekeyInterval = 2 * time.Second
	c, app := connectData(t, cfg)
	info, ok := c.ControlInfo()
	if !ok || info.MaxTunnelPacketSize < 1428 || info.KeyDerivation != client.KeyDerivationTLSExporter {
		t.Fatal("did not negotiate the expected ExpressVPN data channel")
	}
	roundtrip(t, app, echo, info.TunnelIP.AsSlice(), []byte("whole datagram"))
	payload := bytes.Repeat([]byte("vpn"), 466)
	roundtrip(t, app, echo, info.TunnelIP.AsSlice(), payload)
	waitForKeyID(t, c, 1)
	roundtrip(t, app, echo, info.TunnelIP.AsSlice(), payload)
}
