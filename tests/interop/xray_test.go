//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	xrayadapter "github.com/hamedsanaei/openvpn-go/integrations/xray"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/profile"
)

func TestXrayEgressOpenVPN26(t *testing.T) {
	const (
		clientDevice = "tun-m7client"
		serverDevice = "tun-m7server"
		serverIP     = "192.0.2.2"
		tunnelIP     = "10.49.0.2"
		echoIP       = "10.49.0.1"
		tunnelIPv6   = "fd49:67::1000"
		echoIPv6     = "fd49:67::1"
		echoDomain   = "echo.vpn.test"
		port         = 18089
		dnsPort      = 18090
	)
	xray := os.Getenv("XRAY_INTEROP_BIN")
	if xray == "" {
		t.Skip("set XRAY_INTEROP_BIN to Xray-core 26.10.21")
	}
	output, err := exec.CommandContext(t.Context(), xray, "version").Output()
	if err != nil || !strings.HasPrefix(string(output), "Xray 26.10.21 ") || !strings.Contains(string(output), "1b1647c") {
		t.Fatalf("expected pinned Xray 26.10.21, got %v", err)
	}
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, binary, pki)

	serverNS := "ovpn-m7-" + strconv.Itoa(os.Getpid())
	f.namespace = serverNS
	testIP(t, "netns", "add", serverNS)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", serverNS).Run() })
	testIP(t, "link", "add", "m7client", "type", "veth", "peer", "name", "m7server")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "m7client").Run() })
	testIP(t, "link", "set", "m7server", "netns", serverNS)
	testIP(t, "addr", "add", "192.0.2.1/30", "dev", "m7client")
	testIP(t, "link", "set", "m7client", "up")
	testIP(t, "-n", serverNS, "link", "set", "lo", "up")
	testIP(t, "-n", serverNS, "addr", "add", serverIP+"/30", "dev", "m7server")
	testIP(t, "-n", serverNS, "link", "set", "m7server", "up")
	testIP(t, "tuntap", "add", "dev", clientDevice, "mode", "tun")
	t.Cleanup(func() { exec.Command("ip", "link", "del", clientDevice).Run() })
	testIP(t, "address", "add", tunnelIP+"/32", "dev", clientDevice)
	testIP(t, "-6", "address", "add", tunnelIPv6+"/64", "dev", clientDevice, "nodad", "noprefixroute")
	testIP(t, "link", "set", clientDevice, "up")
	testIP(t, "route", "add", echoIP+"/32", "dev", clientDevice, "src", tunnelIP)

	testIP(t, "-6", "route", "add", echoIPv6+"/128", "dev", clientDevice, "src", tunnelIPv6)
	startVPN := func() func() {
		stop := f.launch(t, 1194, "tcp", "tls", false, "--dev", serverDevice, "--local", serverIP, "--keepalive", "1", "4",
			"--server-ipv6", "fd49:67::/64")
		testIP(t, "-n", serverNS, "address", "add", echoIP+"/24", "dev", serverDevice)
		testIP(t, "-n", serverNS, "-6", "address", "add", echoIPv6+"/64", "dev", serverDevice, "nodad")
		testIP(t, "-n", serverNS, "link", "set", serverDevice, "up")
		return stop
	}
	stop := startVPN()
	startNamespaceEcho(t, serverNS, port)
	startNamespaceService(t, serverNS, "TestXrayNamespaceEcho",
		"XRAY_TEST_ECHO_PORT="+strconv.Itoa(port), "XRAY_TEST_ECHO_HOST="+echoIPv6)
	startNamespaceService(t, serverNS, "TestXrayNamespaceDNS",
		"XRAY_TEST_DNS_BIND="+net.JoinHostPort(echoIP, strconv.Itoa(dnsPort)),
		"XRAY_TEST_DNS_AAAA="+echoIPv6)

	text := "client\ndev tun\nproto tcp4-client\nremote " + serverIP + " 1194\nremote-cert-tls server\nverify-x509-name " +
		testkit.TestServerName + " name\n" + profilePKI(pki)
	cfg, _, err := profile.Parse(strings.NewReader(text), profile.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Retry = client.RetryPolicy{MaxAttempts: client.UnlimitedAttempts, InitialBackoff: 25 * time.Millisecond}
	cfg.HandshakeTimeout = 3 * time.Second
	addresses := xrayadapter.Addresses{IPv4: netip.MustParseAddr(tunnelIP), IPv6: netip.PrefixFrom(netip.MustParseAddr(tunnelIPv6), 64)}
	device, err := xrayadapter.OpenDevice(clientDevice, addresses)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	adapter, err := xrayadapter.New(cfg, device, addresses)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ended := make(chan error, 1)
	go func() { ended <- adapter.Run(ctx) }()
	awaitAdapter(t, adapter, ended, 1)

	dns := netip.AddrPortFrom(netip.MustParseAddr(echoIP), dnsPort)
	listeners := map[string]string{
		"IPv4": startXray(t, xray, clientDevice, echoIP, port, netip.AddrPort{}),
		"IPv6": startXray(t, xray, clientDevice, echoIPv6, port, netip.AddrPort{}),
		"DNS":  startXray(t, xray, clientDevice, echoDomain, port, dns),
	}
	probeXrayBatch(t, listeners, "before reconnect")
	stop()
	deadline := time.Now().Add(6 * time.Second)
	for adapter.Stats().Disconnects == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if adapter.Stats().Disconnects == 0 {
		t.Fatal("lost server was not detected")
	}
	startVPN()
	awaitAdapter(t, adapter, ended, 2)
	probeXrayBatch(t, listeners, "after reconnect")
	assertXrayRejectsFallback(t, xray, clientDevice, "localhost", "tcp6", dns)
	if stats := adapter.Stats(); stats.Reconnects != 1 || stats.PacketsSent == 0 || stats.PacketsReceived == 0 {
		t.Fatalf("missing recovered traffic: %+v", stats)
	}
	cancel()
	select {
	case err := <-ended:
		if !errors.Is(err, context.Canceled) || adapter.Stats().State != client.StateClosed {
			t.Fatalf("adapter shutdown: %v, %+v", err, adapter.Stats())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("adapter workers did not stop")
	}
	assertXrayRejectsFallback(t, xray, "m7-nonexistent", "127.0.0.1", "tcp4", netip.AddrPort{})
}

func assertXrayRejectsFallback(t *testing.T, xray, device, destination, network string, dns netip.AddrPort) {
	t.Helper()
	local := net.IPv4(127, 0, 0, 1)
	if network == "tcp6" {
		local = net.IPv6loopback
	}
	target, err := net.ListenTCP(network, &net.TCPAddr{IP: local})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	address := startXray(t, xray, device, destination, target.Addr().(*net.TCPAddr).Port, dns)
	conn, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, "route must fail"); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("Xray did not close the rejected request: %v", err)
	}
	target.SetDeadline(time.Now().Add(500 * time.Millisecond))
	leaked, err := target.Accept()
	if leaked != nil {
		leaked.Close()
		t.Fatalf("Xray reached %s through a fallback route", destination)
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("unexpected listener error: %v", err)
	}
}

func testIP(t *testing.T, args ...string) {
	t.Helper()
	if output, err := exec.CommandContext(t.Context(), "ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("prepare isolated network: %v: %s", err, output)
	}
}

func startNamespaceEcho(t *testing.T, ns string, port int) {
	t.Helper()
	startNamespaceService(t, ns, "TestXrayNamespaceEcho", "XRAY_TEST_ECHO_PORT="+strconv.Itoa(port))
}

func startNamespaceService(t *testing.T, ns, test string, variables ...string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "ip", "netns", "exec", ns, exe, "-test.run", "^"+test+"$")
	cmd.Env = append(os.Environ(), variables...)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	ready := make(chan error, 1)
	go func() {
		buf := make([]byte, len("ready\n"))
		_, err := io.ReadFull(out, buf)
		if err == nil && string(buf) != "ready\n" {
			err = errors.New("namespace service did not start")
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("namespace service did not become ready")
	}
}

func TestXrayNamespaceEcho(t *testing.T) {
	port := os.Getenv("XRAY_TEST_ECHO_PORT")
	if port == "" {
		t.Skip("run by the isolated Xray interoperability test")
	}
	host, family := "0.0.0.0", "4"
	if value := os.Getenv("XRAY_TEST_ECHO_HOST"); value != "" {
		host, family = value, "6"
	}
	addr := net.JoinHostPort(host, port)
	tcp, err := net.Listen("tcp"+family, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp"+family, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 256)
		for {
			n, from, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			udp.WriteTo(buf[:n], from)
		}
	}()
	fmt.Println("ready")
	for {
		conn, err := tcp.Accept()
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			io.Copy(conn, conn)
		}()
	}
}

func startXray(t *testing.T, executable, device, target string, port int, dns netip.AddrPort) string {
	t.Helper()
	local := localPort(t, "tcp")
	example, err := os.ReadFile("../../integrations/xray/openvpn-outbound.json")
	if err != nil {
		t.Fatal(err)
	}
	var outbound struct {
		Tag            string                       `json:"tag"`
		Protocol       string                       `json:"protocol"`
		StreamSettings map[string]map[string]string `json:"streamSettings"`
	}
	if err := json.Unmarshal(example, &outbound); err != nil || outbound.StreamSettings["sockopt"]["interface"] != "ovpn0" {
		t.Fatalf("invalid example outbound: %v", err)
	}
	outbound.StreamSettings["sockopt"]["interface"] = device
	conf := map[string]any{
		"log": map[string]string{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": local, "protocol": "dokodemo-door", "tag": "test-in",
			"settings": map[string]any{"address": target, "port": port, "network": "tcp,udp"},
		}},
		"outbounds": []any{outbound},
	}
	if dns.IsValid() {
		outbound.StreamSettings["sockopt"]["domainStrategy"] = "ForceIPv6"
		conf["dns"] = map[string]any{
			"tag": "vpn-dns", "disableCache": true, "disableFallback": true, "queryStrategy": "UseIPv6",
			"servers": []any{map[string]any{"address": dns.Addr().String(), "port": dns.Port()}},
		}
		conf["outbounds"] = []any{map[string]string{"tag": "blocked", "protocol": "blackhole"}, outbound}
		conf["routing"] = map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{map[string]any{
				"type": "field", "inboundTag": []string{"test-in", "vpn-dns"}, "outboundTag": "openvpn",
			}},
		}
	}
	raw, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), executable, "run", "-config", name)
	log, err := os.Create(filepath.Join(filepath.Dir(name), "xray.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			diagnostics, _ := os.ReadFile(log.Name())
			t.Logf("Xray %s diagnostics:\n%s", target, diagnostics)
		}
	})
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(local)))
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if conn, err := net.DialTimeout("tcp4", address, 50*time.Millisecond); err == nil {
			conn.Close()
			return address
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Xray did not start")
	return ""
}

func awaitAdapter(t *testing.T, adapter *xrayadapter.Adapter, done <-chan error, connections uint64) {
	t.Helper()
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-done:
			t.Fatalf("adapter terminated early: %v", err)
		default:
		}
		if stats := adapter.Stats(); stats.State == client.StateConnected && stats.Connections >= connections {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d successful connections: %+v", connections, adapter.Stats())
}

func probeXrayBatch(t *testing.T, listeners map[string]string, phase string) {
	t.Helper()
	results := make(chan error, len(listeners)*2)
	for target, address := range listeners {
		for _, network := range []string{"tcp4", "udp4"} {
			go func() { results <- probeXray(network, address, phase+" "+target+" "+network) }()
		}
	}
	for range cap(results) {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
}

func probeXray(network, address, payload string) error {
	conn, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		return fmt.Errorf("%s: %w", payload, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, payload); err != nil {
		return fmt.Errorf("%s: %w", payload, err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("%s: %w", payload, err)
	}
	if string(response) != payload {
		return fmt.Errorf("%s: unexpected response %q", payload, response)
	}
	return nil
}

func TestXrayNamespaceDNS(t *testing.T) {
	bind := os.Getenv("XRAY_TEST_DNS_BIND")
	if bind == "" {
		t.Skip("run by the isolated Xray interoperability test")
	}
	answer := netip.MustParseAddr(os.Getenv("XRAY_TEST_DNS_AAAA")).As16()
	socket, err := net.ListenPacket("udp4", bind)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	fmt.Println("ready")
	// These are the only questions sent by the fixture. Additional EDNS
	// records from the client are omitted from the synthetic response.
	questions := [][]byte{
		[]byte("\x04echo\x03vpn\x04test\x00\x00\x1c\x00\x01"),
		[]byte("\x09localhost\x00\x00\x1c\x00\x01"),
	}
	buffer := make([]byte, 4096)
	for {
		n, source, err := socket.ReadFrom(buffer)
		if err != nil {
			t.Fatal(err)
		}
		if n < 12 || buffer[4] != 0 || buffer[5] != 1 {
			continue
		}
		for i, question := range questions {
			if !bytes.HasPrefix(buffer[12:n], question) {
				continue
			}
			response := []byte{buffer[0], buffer[1], 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}
			response = append(response, question...)
			if i == 0 {
				response[7] = 1
				response = append(response, 0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 0, 0, 16)
				response = append(response, answer[:]...)
			} else {
				response[3] = 0x83
			}
			if _, err := socket.WriteTo(response, source); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
}
