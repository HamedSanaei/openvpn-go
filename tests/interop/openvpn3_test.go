//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/profile"
	"github.com/hamedsanaei/openvpn-go/transport"
)

const (
	coreVersion = "3.11.8"
	coreCommit  = "4f3bdef73245d4ee9e8216c5d65baccc9568f6ef"
	labServer   = "198.18.3.1"
	labEcho     = "10.49.0.1"

	connected   = "connected"
	certificate = "certificate"
	authFailed  = "authentication"
)

type conformanceCase struct {
	name, network, protection, tlsVersion, cipher string
	reject                                        string
	password                                      bool
}

type observation struct {
	Outcome   string `json:"outcome"`
	Transport string `json:"transport,omitempty"`
	TLS       string `json:"tls,omitempty"`
	Cipher    string `json:"cipher,omitempty"`
	Traffic   bool   `json:"bidirectional_udp_payload"`
}

type comparison struct {
	Name       string      `json:"name"`
	Protection string      `json:"control_protection"`
	Go         observation `json:"openvpn_go"`
	Core       observation `json:"openvpn_3_core"`
	Result     string      `json:"result"`
}

type conformanceReport struct {
	CoreVersion string       `json:"core_version"`
	CoreCommit  string       `json:"core_commit"`
	CoreSHA256  string       `json:"core_binary_sha256"`
	PeerVersion string       `json:"server_version"`
	PeerSHA256  string       `json:"server_binary_sha256"`
	Cases       []comparison `json:"cases"`
}

func TestOpenVPN3Differential(t *testing.T) {
	core := os.Getenv("OPENVPN3_INTEROP_BIN")
	expectedHash := os.Getenv("OPENVPN3_INTEROP_SHA256")
	if core == "" && expectedHash == "" {
		t.Skip("set OPENVPN3_INTEROP_BIN and OPENVPN3_INTEROP_SHA256 to run differential tests")
	}
	if core == "" || expectedHash == "" || os.Getenv("OPENVPN_INTEROP_BIN") == "" {
		t.Fatal("differential tests require the Core binary and checksum and a pinned server binary")
	}
	server := interopPeer(t)
	sum := binarySHA256(t, core)
	if sum != expectedHash {
		t.Fatal("OpenVPN 3 binary SHA-256 does not match the reference build")
	}
	version, err := exec.CommandContext(t.Context(), core, "--version").CombinedOutput()
	if err != nil || !bytes.Contains(version, []byte("\nOpenVPN core "+coreVersion+" ")) {
		t.Fatalf("expected OpenVPN 3 Core %s: %v", coreVersion, err)
	}
	peerVersion := os.Getenv("OPENVPN_INTEROP_VERSION")
	if peerVersion == "" {
		peerVersion = "2.6.23"
	}
	report := conformanceReport{
		CoreVersion: coreVersion, CoreCommit: coreCommit, CoreSHA256: sum,
		PeerVersion: peerVersion, PeerSHA256: binarySHA256(t, server),
	}
	t.Cleanup(func() {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("differential conformance results:\n%s", data)
		if path := os.Getenv("OPENVPN3_COMPARISON_JSON"); path != "" {
			if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
				t.Errorf("write conformance report: %v", err)
			}
		}
	})
	ns := prepareCoreNamespace(t)
	for _, scenario := range []conformanceCase{
		{"udp-tls12-aes128", "udp", "tls", "1.2", "AES-128-GCM", "", false},
		{"tcp-tls13-aes256-password", "tcp", "tls-auth", "1.3", "AES-256-GCM", "", true},
		{"udp-tls13-chacha-tls-crypt", "udp", "tls-crypt", "1.3", "CHACHA20-POLY1305", "", false},
		{"udp-tls13-aes256-v2-cookie", "udp", "v2-cookie", "1.3", "AES-256-GCM", "", false},
		{"wrong-server-name", "tcp", "tls", "1.3", "AES-256-GCM", "name", false},
		{"wrong-ca", "tcp", "tls", "1.3", "AES-256-GCM", "ca", false},
		{"wrong-password", "tcp", "tls", "1.3", "AES-256-GCM", "password", true},
		{"retry-directive", "udp", "tls", "1.2", "AES-256-GCM", "", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			pki := testkit.NewPKI(t)
			f := makeFixture(t, server, pki)
			port := localPort(t, scenario.network)
			f.launch(t, port, scenario.network, scenario.protection, scenario.password,
				"--dev", "tun-oracle", "--local", labServer, "--tls-version-min", scenario.tlsVersion,
				"--tls-version-max", scenario.tlsVersion, "--data-ciphers", scenario.cipher, "--verb", "3")
			testIP(t, "address", "add", labEcho+"/24", "dev", "tun-oracle")
			testIP(t, "link", "set", "tun-oracle", "up")
			echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(labEcho)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { echo.Close() })
			text, credentials := coreProfile(t, f, scenario, pki, port)
			result := comparison{Name: scenario.name, Protection: scenario.protection, Result: "mismatch"}
			defer func() { report.Cases = append(report.Cases, result) }()
			goOK := t.Run("go", func(t *testing.T) {
				probeGo(t, text, credentials, echo, &result.Go)
			})
			coreOK := t.Run("core", func(t *testing.T) {
				probeCore(t, core, ns, text, credentials, echo, &result.Core)
			})
			want := observation{Outcome: connected, Transport: scenario.network, TLS: scenario.tlsVersion, Cipher: scenario.cipher, Traffic: true}
			wantGo, wantCore := want, want
			switch scenario.reject {
			case "name", "ca":
				wantGo, wantCore = observation{Outcome: certificate}, observation{Outcome: certificate}
			case "password":
				wantGo, wantCore = observation{Outcome: authFailed}, observation{Outcome: authFailed}
			}
			if !goOK || !coreOK || result.Go != wantGo || result.Core != wantCore {
				t.Errorf("unexpected difference or failed expectation: Go %+v, Core %+v; want Go %+v, Core %+v",
					result.Go, result.Core, wantGo, wantCore)
			} else {
				result.Result = "match"
			}
		})
	}
}

func binarySHA256(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func prepareCoreNamespace(t *testing.T) string {
	t.Helper()
	ns := "ovpn3-" + strconv.Itoa(os.Getpid())
	testIP(t, "netns", "add", ns)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
	testIP(t, "link", "add", "oracle-server", "type", "veth", "peer", "name", "oracle-client", "netns", ns)
	t.Cleanup(func() { exec.Command("ip", "link", "del", "oracle-server").Run() })
	testIP(t, "address", "add", labServer+"/30", "dev", "oracle-server")
	testIP(t, "link", "set", "oracle-server", "up")
	testIP(t, "-n", ns, "link", "set", "lo", "up")
	testIP(t, "-n", ns, "address", "add", "198.18.3.2/30", "dev", "oracle-client")
	testIP(t, "-n", ns, "link", "set", "oracle-client", "up")
	return ns
}

func coreProfile(t *testing.T, f fixture, scenario conformanceCase, pki testkit.PKI, port uint16) (string, *client.Credentials) {
	t.Helper()
	proto := "udp4"
	if scenario.network == "tcp" {
		proto = "tcp4-client"
	}
	name := testkit.TestServerName
	switch scenario.reject {
	case "name":
		name = "wrong.example.test"
	case "ca":
		pki.CA = testkit.NewPKI(t).CA
	}
	text := fmt.Sprintf("client\ndev tun\nproto %s\nremote %s %d\nremote-cert-tls server\nverify-x509-name %s name\ndata-ciphers %s\ntls-version-min %s\n",
		proto, labServer, port, name, scenario.cipher, scenario.tlsVersion) + profilePKI(pki)
	if option, material := profileProtection(f, scenario.protection); option != "" {
		text += profileSection(option, material)
		if scenario.protection == "tls-auth" {
			text += "auth SHA256\nkey-direction 1\n"
		}
	}
	if scenario.name == "retry-directive" {
		text += "connect-retry-max 1\n"
	}
	if !scenario.password {
		return text, nil
	}
	credentials := &client.Credentials{Username: username, Password: password}
	if scenario.reject == "password" {
		credentials.Password = "lab-incorrect-password"
	}
	return text + "auth-user-pass\n", credentials
}

func probeGo(t *testing.T, text string, creds *client.Credentials, echo *net.UDPConn, result *observation) {
	t.Helper()
	cfg, _, err := profile.Parse(strings.NewReader(text), profile.Options{Credentials: creds})
	if err != nil {
		t.Fatalf("generated Go profile: %v", err)
	}
	cfg.HandshakeTimeout = 5 * time.Second
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Connect(t.Context()); err != nil {
		var failure *client.Error
		if !errors.As(err, &failure) {
			t.Fatal("expected a typed OpenVPN Go error")
		}
		result.Outcome = string(failure.Code)
		switch failure.Code {
		case client.CodeCertificate:
			result.Outcome = certificate
		case client.CodeAuthentication:
			result.Outcome = authFailed
		}
		return
	}
	info, ok := c.ControlInfo()
	if !ok {
		t.Fatal("Go negotiation missing after successful connect")
	}
	endpoint, ok := c.ActiveEndpoint()
	if !ok || len(endpoint.Network) < 3 {
		t.Fatal("Go endpoint missing after successful connect")
	}
	version := ""
	switch info.TLSVersion {
	case tls.VersionTLS12:
		version = "1.2"
	case tls.VersionTLS13:
		version = "1.3"
	}
	*result = observation{Outcome: connected, Transport: endpoint.Network[:3], TLS: version, Cipher: info.DataCipher}
	device, app := testkit.PacketPipe(8, transport.DefaultPacketSize)
	defer device.Close()
	defer app.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, device) }()
	defer func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Go packet forwarding: %v", err)
		}
	}()
	roundtrip(t, app, echo, info.TunnelIP.AsSlice(), []byte("differential echo"))
	result.Traffic = true
}

var (
	coreTLS    = regexp.MustCompile(`SSL Handshake:[^\n]*\bTLSv1\.([23])\b`)
	coreCipher = regexp.MustCompile(`(?m)^[ \t]*data channel: cipher (AES-(?:128|256)-GCM|CHACHA20-POLY1305),`)
	coreProto  = regexp.MustCompile(`(?m)EVENT: CONNECTED [^\n]*?/(UDP|TCP)v?[46]?[ /]`)
)

func coreObservation(log []byte) observation {
	if bytes.Contains(log, []byte("EVENT: CONNECTED ")) {
		out := observation{Outcome: connected}
		if m := coreTLS.FindSubmatch(log); m != nil {
			out.TLS = "1." + string(m[1])
		}
		if m := coreCipher.FindSubmatch(log); m != nil {
			out.Cipher = strings.ToUpper(string(m[1]))
		}
		if m := coreProto.FindSubmatch(log); m != nil {
			out.Transport = strings.ToLower(string(m[1]))
		}
		return out
	}
	if bytes.Contains(log, []byte("CERT_VERIFY_FAIL")) ||
		bytes.Contains(log, []byte("VERIFY X509NAME ERROR")) ||
		bytes.Contains(log, []byte("certificate verify failed")) {
		return observation{Outcome: certificate}
	}
	if bytes.Contains(log, []byte("EVENT: AUTH_FAILED")) {
		return observation{Outcome: authFailed}
	}
	return observation{}
}

func probeCore(t *testing.T, core, ns, text string, creds *client.Credentials, echo *net.UDPConn, result *observation) {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "generated.ovpn")
	if err := os.WriteFile(config, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.CreateTemp(dir, "core-log-")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	args := []string{"netns", "exec", ns, core, "--timeout", "8"}
	if creds != nil {
		// These values are generated lab credentials. The CLI accepts the
		// username and password through options.
		args = append(args, "--username", creds.Username, "--password", creds.Password)
	}
	cmd := exec.CommandContext(ctx, "ip", append(args, config)...)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal("could not start pinned OpenVPN 3 Core client")
	}
	done := make(chan struct{})
	go func() {
		cmd.Wait()
		close(done)
	}()
	defer func() { cancel(); <-done }()

	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		raw, err := os.ReadFile(log.Name())
		if err != nil {
			t.Fatal(err)
		}
		*result = coreObservation(raw)
		if result.Outcome != "" {
			break
		}
		select {
		case <-tick.C:
			continue
		case <-ctx.Done():
			t.Fatal("OpenVPN 3 Core produced no recognized outcome before the deadline")
		case <-done:
			raw, err = os.ReadFile(log.Name())
			if err != nil {
				t.Fatal(err)
			}
			*result = coreObservation(raw)
			if result.Outcome == "" {
				t.Fatal("OpenVPN 3 Core exited without a recognized outcome")
			}
		}
		break
	}
	if result.Outcome != connected {
		return
	}
	probeCoreTraffic(t, ctx, ns, echo)
	result.Traffic = true
}

func probeCoreTraffic(t *testing.T, ctx context.Context, ns string, echo *net.UDPConn) {
	t.Helper()
	const probe = `import socket, sys
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
    conn.settimeout(3)
    conn.connect((sys.argv[1], int(sys.argv[2])))
    conn.send(b"differential echo")
    if conn.recv(256) != b"response: differential echo":
        raise SystemExit("unexpected tunnel payload")`
	port := echo.LocalAddr().(*net.UDPAddr).Port
	if err := echo.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, "python3", "-c", probe, labEcho, strconv.Itoa(port))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	var buffer [256]byte
	n, remote, err := echo.ReadFromUDP(buffer[:])
	if err != nil || !bytes.Equal(buffer[:n], []byte("differential echo")) ||
		!(&net.IPNet{IP: net.ParseIP("10.49.0.0"), Mask: net.CIDRMask(24, 32)}).Contains(remote.IP) {
		t.Fatalf("OpenVPN 3 Core client-to-server tunnel probe failed: %v", err)
	}
	if _, err := echo.WriteToUDP([]byte("response: differential echo"), remote); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatalf("OpenVPN 3 Core server-to-client tunnel probe failed: %v", err)
	}
}
