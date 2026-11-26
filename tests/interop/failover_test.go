//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
	"github.com/hamedsanaei/openvpn-go/transport"
)

const alternateName = "other-vpn.example.test"

func TestFailoverReconnectOpenVPN26(t *testing.T) {
	peer := interopPeer(t)
	firstPKI := testkit.NewPKI(t)
	secondPKI := testkit.NewPKIWithServer(t, func(cert *x509.Certificate) {
		cert.Subject.CommonName = alternateName
		cert.DNSNames = []string{alternateName}
	})
	trust := bytes.Join([][]byte{firstPKI.CA, secondPKI.CA}, nil)
	// Both servers verify the first fixture's client certificate.
	secondPKI.CA = firstPKI.CA
	first, second := makeFixture(t, peer, firstPKI), makeFixture(t, peer, secondPKI)

	silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	portA, portB := localPort(t, "tcp"), localPort(t, "udp")
	startA := func() (func(), *net.UDPConn) {
		return launchFailoverPeer(t, first, portA, "tcp", "tun-m5a", "10.51.0.0", "10.51.0.1", "--auth-gen-token", "120", "120")
	}
	stopA, echoA := startA()
	stopB, echoB := launchFailoverPeer(t, second, portB, "udp", "tun-m5b", "10.52.0.0", "10.52.0.1")

	cfg := first.config(firstPKI, "tcp", "tls", portA, true)
	cfg.TLS.CA = trust
	activeTCP := cfg.Endpoints[0]
	activeUDP := client.Endpoint{Host: "127.0.0.1", Port: portB, Network: "udp4", ServerName: alternateName}
	cfg.Endpoints = []client.Endpoint{
		{Host: "127.0.0.1", Port: uint16(silent.LocalAddr().(*net.UDPAddr).Port), Network: "udp4", ServerName: "silent.example.test"},
		activeTCP,
		activeUDP,
	}
	cfg.HandshakeTimeout = time.Second
	cfg.RekeyInterval = time.Second
	cfg.Retry.InitialBackoff = 25 * time.Millisecond

	var mu sync.Mutex
	var choices []string
	names := make(chan string, 8)
	// Reuse packet framing over a custom connected transport. The hook
	// receives the original destination, and the TLS client still owns SNI.
	proxy := (transport.SocketDialer{}).WithDialContext(func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		choices = append(choices, network)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, network, address string) (transport.PacketConn, error) {
		raw, err := proxy.DialPacket(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &helloObserver{PacketConn: raw, nextID: 1, names: names}, nil
	})
	c, app := connectData(t, cfg)
	waitForConnection(t, c, 1, activeTCP)
	assertPeerSNI(t, names, testkit.TestServerName)
	if info, ok := c.ControlInfo(); !ok {
		t.Fatal("missing initial control negotiation")
	} else {
		roundtrip(t, app, echoA, info.TunnelIP.AsSlice(), []byte("before failover"))
	}
	// The source server uses a session token on rekey. The second server
	// only accepts the original synthetic username and password.
	waitForKeyID(t, c, 1)
	stopA()
	waitForConnection(t, c, 2, activeUDP)
	assertPeerSNI(t, names, alternateName)
	if info, ok := c.ControlInfo(); !ok {
		t.Fatal("missing UDP recovery negotiation")
	} else {
		roundtrip(t, app, echoB, info.TunnelIP.AsSlice(), []byte("on UDP fallback"))
	}

	echoA.Close()
	_, echoA = startA()
	stopB()
	waitForConnection(t, c, 3, activeTCP)
	assertPeerSNI(t, names, testkit.TestServerName)
	if info, ok := c.ControlInfo(); !ok {
		t.Fatal("missing restarted server negotiation")
	} else {
		roundtrip(t, app, echoA, info.TunnelIP.AsSlice(), []byte("after server restart"))
	}

	mu.Lock()
	got := slices.Clone(choices)
	mu.Unlock()
	want := []string{"udp4", "tcp4", "udp4", "udp4", "tcp4"}
	if !slices.Equal(got, want) {
		t.Fatalf("dial order = %v, want %v", got, want)
	}
	stats := c.Stats()
	for deadline := time.Now().Add(time.Second); stats.PacketsReceived < 3 && time.Now().Before(deadline); stats = c.Stats() {
		time.Sleep(time.Millisecond)
	}
	if stats.Attempts != 5 || stats.AttemptFailures != 2 || stats.Connections != 3 ||
		stats.Disconnects != 2 || stats.Reconnects != 2 || stats.ActiveEndpointIndex != 1 ||
		stats.PacketsSent < 3 || stats.PacketsReceived < 3 {
		t.Fatalf("unexpected lifecycle stats: %+v", stats)
	}
}

func TestFailoverStopsOnOpenVPNTLSRejection(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, binary, pki)
	port := f.start(t, "tcp", "tls", true)
	for _, mode := range []string{"wrong_identity", "wrong_CA", "wrong_password"} {
		t.Run(mode, func(t *testing.T) {
			cfg := f.config(pki, "tcp", "tls", port, true)
			cfg.Endpoints = append(cfg.Endpoints, cfg.Endpoints[0])
			want := client.CodeCertificate
			switch mode {
			case "wrong_identity":
				cfg.Endpoints[0].ServerName = alternateName
			case "wrong_CA":
				cfg.TLS.CA = testkit.NewPKI(t).CA
			case "wrong_password":
				cfg.Credentials.Password = "synthetic-invalid-password"
				want = client.CodeAuthentication
			}
			c, err := client.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			err = c.Connect(t.Context())
			var failure *client.Error
			if !errors.As(err, &failure) || failure.Code != want {
				t.Fatalf("Connect = %v, want %s", err, want)
			}
			if c.Stats().Attempts != 1 || c.State() != client.StateIdle {
				t.Fatal("a terminal rejection advanced the candidate list")
			}
		})
	}
}

func launchFailoverPeer(t *testing.T, f fixture, port uint16, network, device, subnet, ip string, extra ...string) (func(), *net.UDPConn) {
	t.Helper()
	opts := []string{"--dev", device, "--server", subnet, "255.255.255.0", "--keepalive", "1", "4", "--verb", "3"}
	stop := f.launch(t, port, network, "tls", true, append(opts, extra...)...)
	configureLink(t, device, ip+"/24")
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	return stop, echo
}

func waitForConnection(t *testing.T, c *client.Client, successes uint64, expected client.Endpoint) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ep, ok := c.ActiveEndpoint(); ok && ep == expected && c.Stats().Connections == successes {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("did not establish connection %d: %+v", successes, c.Stats())
}

func assertPeerSNI(t *testing.T, names <-chan string, expected string) {
	t.Helper()
	select {
	case got := <-names:
		if got != expected {
			t.Fatalf("TLS ClientHello SNI = %q, want %q", got, expected)
		}
	case <-time.After(time.Second):
		t.Fatal("missing TLS ClientHello")
	}
}

// The plain control test modes expose the TLS ClientHello. The observer
// assembles its initial record from ordered OpenVPN control packets.
type helloObserver struct {
	transport.PacketConn
	nextID uint32
	hello  []byte
	names  chan<- string
}

func (o *helloObserver) WritePacket(ctx context.Context, packet []byte) error {
	if o.names != nil && len(packet) > wire.PrefixSize {
		p, err := wire.ParseControl(packet[:wire.PrefixSize], packet[wire.PrefixSize:])
		if err == nil && p.Opcode == wire.Control && p.KeyID == 0 && p.ID == o.nextID {
			o.nextID++
			o.hello = append(o.hello, p.Payload...)
			if len(o.hello) >= 5 && len(o.hello) >= 5+int(binary.BigEndian.Uint16(o.hello[3:5])) {
				o.names <- readClientSNI(o.hello)
				o.names = nil
				o.hello = nil
			}
		}
	}
	return o.PacketConn.WritePacket(ctx, packet)
}

func readClientSNI(record []byte) string {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var name string
	server := tls.Server(&helloReader{Conn: a, payload: bytes.NewReader(record)}, &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			name = info.ServerName
			return nil, io.EOF
		},
	})
	server.Handshake()
	return name
}

type helloReader struct {
	net.Conn
	payload *bytes.Reader
}

func (r *helloReader) Read(dst []byte) (int, error)  { return r.payload.Read(dst) }
func (r *helloReader) Write(src []byte) (int, error) { return len(src), nil }
