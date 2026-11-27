//go:build linux

package interop_test

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

const dns26Flag = 1 << 6
const dns27Flag = 1 << 11

func configureDNSPush(t *testing.T, f fixture, mask int) {
	t.Helper()
	// The stock server exposes peer info to the client-connect hook. This
	// fixture chooses modern DNS options as an operator's hook could.
	script := fmt.Sprintf(`
#!/bin/sh
flags="$IV_PROTO"
if [ -z "$flags" ]; then flags=0; fi
case "$flags" in
    *[!0-9]*) exit 1 ;;
esac
printf '%%s\n' "$flags" > dns-peer-flags
if [ "$(( flags & %d ))" -ne 0 ]; then
    printf '%%s\n' 'push "dns server 2 address 10.49.0.53"' 'push "dns server 2 resolve-domains corp.example"' 'push "dns search-domains corp.example"' > "$1"
fi
`, mask)
	if err := os.WriteFile(filepath.Join(f.dir, "select-dns"), []byte(strings.TrimLeft(script, "\n")), 0700); err != nil {
		t.Fatal(err)
	}
}

func peerDNSFlags(t *testing.T, f fixture) int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, "dns-peer-flags"))
	if err != nil {
		t.Fatal(err)
	}
	bits, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return bits & (dns26Flag | dns27Flag)
}

func TestDNSCapabilitiesOpenVPN(t *testing.T) {
	binary := interopPeer(t)
	mask := dns26Flag
	if os.Getenv("OPENVPN_INTEROP_VERSION") == "2.7.9" {
		mask = dns27Flag
	}
	for _, tc := range []struct {
		name        string
		advertise   bool
		policy      tunnel.PushAction
		wantAddress string
		wantBits    int
	}{
		{"legacy", false, tunnel.PushAccept, "10.49.0.54:53", 0},
		{"modern", true, tunnel.PushAccept, "10.49.0.53:53", dns26Flag | dns27Flag},
		{"ignore", true, tunnel.PushIgnore, "", 0},
		{"reject", true, tunnel.PushReject, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := testkit.NewPKI(t)
			f := makeFixture(t, binary, pki)
			configureDNSPush(t, f, mask)
			port := f.start(t, "tcp", "tls", false, "--script-security", "2", "--client-connect", "./select-dns",
				"--push", "dhcp-option DNS 10.49.0.54")
			cfg := f.config(pki, "tcp", "tls", port, false)
			cfg.AdvertiseDNS, cfg.PushPolicy.DNS = tc.advertise, tc.policy
			c, err := client.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			err = c.Connect(t.Context())
			if flags := peerDNSFlags(t, f); flags != tc.wantBits {
				t.Fatalf("received DNS capability bits %#x, want %#x", flags, tc.wantBits)
			}
			if tc.policy == tunnel.PushReject {
				var failure *client.Error
				if !errors.As(err, &failure) || failure.Code != client.CodeProtocol {
					t.Fatalf("expected authenticated DNS rejection, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			info, ok := c.ControlInfo()
			if !ok {
				t.Fatal("missing authenticated DNS")
			}
			dns := info.Tunnel.DNS()
			if tc.wantAddress == "" {
				if len(dns.Servers) != 0 {
					t.Fatal("ignored DNS options were published")
				}
				return
			}
			if len(dns.Servers) != 1 || len(dns.Servers[0].Addresses) != 1 ||
				dns.Servers[0].Addresses[0] != netip.MustParseAddrPort(tc.wantAddress) {
				t.Fatalf("unexpected authenticated DNS: %+v", dns)
			}
			if tc.advertise && (len(dns.SearchDomains) != 1 || dns.SearchDomains[0] != "corp.example" ||
				len(dns.Servers[0].ResolveDomains) != 1 || dns.Servers[0].ResolveDomains[0] != "corp.example") {
				t.Fatal("typed split DNS metadata was lost")
			}
		})
	}
}

func TestDNSCapabilitiesOpenVPN3(t *testing.T) {
	core := os.Getenv("OPENVPN3_INTEROP_BIN")
	if core == "" {
		t.Skip("set OPENVPN3_INTEROP_BIN for the Core DNS capability check")
	}
	verifyCoreBuild(t, core, os.Getenv("OPENVPN3_INTEROP_SHA256"))
	server := interopPeer(t)
	ns := prepareCoreNamespace(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, server, pki)
	configureDNSPush(t, f, dns26Flag|dns27Flag)
	port := f.start(t, "tcp", "tls", false, "--dev", "tun-oracle", "--local", labServer, "--script-security", "2",
		"--client-connect", "./select-dns", "--push", "dhcp-option DNS 10.49.0.54")
	testIP(t, "address", "add", labEcho+"/24", "dev", "tun-oracle")
	testIP(t, "link", "set", "dev", "tun-oracle", "up")
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(labEcho)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	scenario := conformanceCase{network: "tcp", protection: "tls", tlsVersion: "1.2", cipher: "AES-256-GCM"}
	profile, creds := coreProfile(t, f, scenario, pki, port)
	var result observation
	probeCore(t, core, ns, profile, creds, echo, &result)
	if result.Outcome != connected || !result.Traffic {
		t.Fatalf("Core did not forward traffic after the conditional DNS push: %+v", result)
	}
	if flags := peerDNSFlags(t, f); flags != dns27Flag {
		t.Fatalf("pinned Core DNS capability bits %#x, want %#x", flags, dns27Flag)
	}
}
