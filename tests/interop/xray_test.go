//go:build linux

package interop_test

import (
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
		port         = 18089
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
	testIP(t, "link", "set", clientDevice, "up")
	testIP(t, "route", "add", echoIP+"/32", "dev", clientDevice, "src", tunnelIP)

	startVPN := func() func() {
		stop := f.launch(t, 1194, "tcp", "tls", false, "--dev", serverDevice, "--local", serverIP, "--keepalive", "1", "4")
		testIP(t, "-n", serverNS, "address", "add", echoIP+"/24", "dev", serverDevice)
		testIP(t, "-n", serverNS, "link", "set", serverDevice, "up")
		return stop
	}
	stop := startVPN()
	startNamespaceEcho(t, serverNS, port)

	text := "client\ndev tun\nproto tcp4-client\nremote " + serverIP + " 1194\nremote-cert-tls server\nverify-x509-name " +
		testkit.TestServerName + " name\n" + profilePKI(pki)
	cfg, _, err := profile.Parse(strings.NewReader(text), profile.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Retry = client.RetryPolicy{MaxAttempts: client.UnlimitedAttempts, InitialBackoff: 25 * time.Millisecond}
	cfg.HandshakeTimeout = 3 * time.Second
	addresses := xrayadapter.Addresses{IPv4: netip.MustParseAddr(tunnelIP)}
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

	listen := startXray(t, xray, clientDevice, echoIP, port)
	for _, network := range []string{"tcp4", "udp4"} {
		probeXray(t, network, listen, "before reconnect")
	}
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
	for _, network := range []string{"tcp4", "udp4"} {
		probeXray(t, network, listen, "after reconnect")
	}
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
	assertXrayRejectsMissingDevice(t, xray)
}

func assertXrayRejectsMissingDevice(t *testing.T, xray string) {
	t.Helper()
	target, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	address := startXray(t, xray, "m7-nonexistent", "127.0.0.1", target.Addr().(*net.TCPAddr).Port)
	conn, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	io.WriteString(conn, "binding must fail")
	target.SetDeadline(time.Now().Add(500 * time.Millisecond))
	leaked, err := target.Accept()
	if leaked != nil {
		leaked.Close()
		t.Fatal("Xray tried the unbound route after the selected interface was missing")
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
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "ip", "netns", "exec", ns, exe, "-test.run", "^TestXrayNamespaceEcho$")
	cmd.Env = append(os.Environ(), "XRAY_TEST_ECHO_PORT="+strconv.Itoa(port))
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
			err = errors.New("echo child did not start")
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("echo child did not become ready")
	}
}

func TestXrayNamespaceEcho(t *testing.T) {
	port := os.Getenv("XRAY_TEST_ECHO_PORT")
	if port == "" {
		t.Skip("run by the isolated Xray interoperability test")
	}
	addr := "0.0.0.0:" + port
	tcp, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", addr)
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

func startXray(t *testing.T, executable, device, target string, port int) string {
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
			"listen": "127.0.0.1", "port": local, "protocol": "dokodemo-door",
			"settings": map[string]any{"address": target, "port": port, "network": "tcp,udp"},
		}},
		"outbounds": []any{outbound},
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
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
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

func probeXray(t *testing.T, network, address, payload string) {
	t.Helper()
	conn, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil || string(response) != payload {
		t.Fatalf("Xray %s echo failed: %v", network, err)
	}
}
