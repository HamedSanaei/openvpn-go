//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	xrayadapter "github.com/hamedsanaei/openvpn-go/integrations/xray"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/profile"
)

func TestTunnelDNSAcrossReconnectOpenVPN26(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, binary, pki)
	const (
		tun           = "tun-dns-client"
		peerTun       = "tun-dns-server"
		transportPeer = "192.0.2.2"
		vpnDNS        = "10.49.0.1"
	)
	firstServer := netip.MustParseAddrPort(vpnDNS + ":18183")
	nextServer := netip.MustParseAddrPort(vpnDNS + ":18184")
	before, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		after, err := os.ReadFile("/etc/resolv.conf")
		if err != nil || !bytes.Equal(before, after) {
			t.Error("host resolver configuration changed")
		}
	}()

	ns := "ovpn-dns-" + strconv.Itoa(os.Getpid())
	f.namespace = ns
	testIP(t, "netns", "add", ns)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
	testIP(t, "link", "add", "dnsclient", "type", "veth", "peer", "name", "dnsserver", "netns", ns)
	t.Cleanup(func() { exec.Command("ip", "link", "del", "dnsclient").Run() })
	testIP(t, "addr", "add", "192.0.2.1/30", "dev", "dnsclient")
	testIP(t, "link", "set", "dnsclient", "up")
	testIP(t, "-n", ns, "link", "set", "lo", "up")
	testIP(t, "-n", ns, "addr", "add", transportPeer+"/30", "dev", "dnsserver")
	testIP(t, "-n", ns, "link", "set", "dnsserver", "up")
	testIP(t, "tuntap", "add", "dev", tun, "mode", "tun")
	t.Cleanup(func() { exec.Command("ip", "link", "del", tun).Run() })
	testIP(t, "address", "add", "10.49.0.2/32", "dev", tun)
	testIP(t, "link", "set", tun, "up")
	testIP(t, "route", "add", vpnDNS+"/32", "dev", tun, "src", "10.49.0.2")
	for _, server := range []netip.AddrPort{firstServer, nextServer} {
		startNamespaceEcho(t, ns, int(server.Port()))
	}
	launch := func(server netip.AddrPort) func() {
		stop := f.launch(t, 1194, "tcp", "tls", false, "--dev", peerTun, "--local", transportPeer,
			"--keepalive", "1", "4", "--push", "dns server 0 address "+server.String())
		testIP(t, "-n", ns, "address", "add", vpnDNS+"/24", "dev", peerTun)
		testIP(t, "-n", ns, "link", "set", peerTun, "up")
		return stop
	}
	stopFirst := launch(firstServer)

	text := fmt.Sprintf("client\ndev tun\nremote %s 1194 tcp4\nremote-cert-tls server\nverify-x509-name %s name\n", transportPeer, testkit.TestServerName) + profilePKI(pki)
	cfg, _, err := profile.Parse(strings.NewReader(text), profile.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnectTimeout, cfg.HandshakeTimeout = time.Second, 3*time.Second
	cfg.Retry = client.RetryPolicy{MaxAttempts: client.UnlimitedAttempts, InitialBackoff: 15 * time.Millisecond}
	device, err := xrayadapter.OpenDevice(tun, xrayadapter.Addresses{IPv4: netip.MustParseAddr("10.49.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	pending := make(chan uint64, 3)
	ack := make(chan struct{}, 2)
	rolledBack := make(chan uint64, 3)
	adapter, err := xrayadapter.NewConfigured(cfg, device, xrayadapter.Options{
		DNSDialer: xrayadapter.BindDNSDevice(tun),
		Configure: func(ctx context.Context, gen client.TunnelGeneration) (func(), error) {
			if gen.Control.TunnelIP.String() != "10.49.0.2" {
				return nil, errors.New("unexpected assigned test address")
			}
			pending <- gen.Number
			select {
			case <-ack:
				return func() { rolledBack <- gen.Number }, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 18*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- adapter.Run(ctx) }()

	waitNumber := func(events <-chan uint64, expected uint64) {
		t.Helper()
		select {
		case number := <-events:
			if number != expected {
				t.Fatalf("generation = %d, want %d", number, expected)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for the tunnel generation")
		}
	}
	deny := func(gen uint64, addr netip.AddrPort) {
		t.Helper()
		conn, err := adapter.DialDNS(ctx, gen, "udp", addr)
		if conn != nil {
			conn.Close()
		}
		if !errors.Is(err, xrayadapter.ErrDNSUnavailable) {
			t.Fatalf("unacknowledged or unauthorized DNS socket: %v", err)
		}
	}
	checkTraffic := func(gen uint64, endpoint netip.AddrPort) net.Conn {
		t.Helper()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			number, dns, ok := adapter.ActiveDNS()
			if ok {
				if number != gen || len(dns.Servers) != 1 || len(dns.Servers[0].Addresses) != 1 || dns.Servers[0].Addresses[0] != endpoint {
					t.Fatalf("unexpected active DNS configuration: %d, %+v", number, dns)
				}
				break
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				t.Fatal("acknowledged DNS configuration did not become active")
			}
		}
		conn, err := adapter.DialDNS(ctx, gen, "udp", endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		// An opaque DNS query traverses the adapter's UDP socket to the
		// echo fixture. DNS message interpretation belongs to the caller.
		query := []byte{0x31, 0x13, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
		if _, err := conn.Write(query); err != nil {
			t.Fatal(err)
		}
		var buf [256]byte
		if n, err := conn.Read(buf[:]); err != nil || !bytes.Equal(buf[:n], query) {
			t.Fatalf("DNS socket round trip did not follow the tunnel: %v", err)
		}
		return conn
	}

	waitNumber(pending, 1)
	deny(1, firstServer)
	ack <- struct{}{}
	first := checkTraffic(1, firstServer)
	defer first.Close()

	// The numeric server is reachable via the veth but must never be
	// selected from the adapter's DNS configuration or as a fallback.
	outside := netip.AddrPortFrom(netip.MustParseAddr(transportPeer), firstServer.Port())
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", outside.String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	deny(1, outside)
	if conn, err := xrayadapter.BindDNSDevice("missing-dns-tun")(ctx, "tcp", outside); err == nil {
		conn.Close()
		t.Fatal("failed interface binding fell back to an unbound socket")
	}

	stopFirst()
	waitNumber(rolledBack, 1)
	deny(1, firstServer)
	if _, err := first.Write([]byte("stale")); !errors.Is(err, xrayadapter.ErrDNSUnavailable) {
		t.Fatalf("old generation socket survived rollback: %v", err)
	}
	launch(nextServer)
	waitNumber(pending, 2)
	deny(2, nextServer)
	if _, _, active := adapter.ActiveDNS(); active {
		t.Fatal("a pending configuration exposed DNS")
	}
	ack <- struct{}{}
	second := checkTraffic(2, nextServer)
	defer second.Close()
	deny(2, firstServer)
	deny(1, nextServer)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("adapter shutdown: %v", err)
	}
	if number := <-rolledBack; number != 2 {
		t.Fatalf("last rollback = %d, want 2", number)
	}
}
