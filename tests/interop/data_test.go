//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
	"github.com/hamedsanaei/openvpn-go/transport"
)

const dataDevice = "tun-m3"

func TestDataOpenVPN26(t *testing.T) {
	binaryPath := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, binaryPath, pki)
	for _, network := range []string{"udp", "tcp"} {
		for _, mode := range []string{"tls", "tls-auth", "tls-crypt", "v2", "v2-cookie"} {
			for _, auth := range []bool{false, true} {
				for _, version := range []string{"1.2", "1.3"} {
					for _, cipher := range []string{"AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305"} {
						t.Run(fmt.Sprintf("%s/%s/auth=%t/TLS%s/%s", network, mode, auth, version, cipher), func(t *testing.T) {
							port, echo := startDataPeer(t, f, network, mode, auth, version, cipher)
							cfg := f.config(pki, network, mode, port, auth)
							cfg.DataCiphers = []string{cipher}
							c, app := connectData(t, cfg)
							info, ok := c.ControlInfo()
							wantVersion := uint16(tls.VersionTLS12)
							if version == "1.3" {
								wantVersion = tls.VersionTLS13
							}
							if !ok || info.DataCipher != cipher || info.TLSVersion != wantVersion {
								t.Fatalf("negotiation = %+v", info)
							}
							roundtrip(t, app, echo, info.TunnelIP.AsSlice(), []byte("initial generation"))
						})
					}
				}
			}
		}
	}
}

func TestDataIPv6OpenVPN26(t *testing.T) {
	binaryPath := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, binaryPath, pki)
	port := f.start(t, "udp", "tls", false, "--dev", dataDevice, "--proto", "udp6", "--local", "::1",
		"--server-ipv6", "fd4d:49::/64", "--verb", "3")
	configureTestLink(t, "fd4d:49::1/64", "nodad")
	echo, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("fd4d:49::1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })

	cfg := f.config(pki, "udp", "tls", port, false)
	cfg.Endpoints[0].Network, cfg.Endpoints[0].Host = "udp6", "::1"
	c, app := connectData(t, cfg)
	info, ok := c.ControlInfo()
	if !ok || !info.TunnelIPv6.IsValid() {
		t.Fatalf("expected an assigned IPv6 address, got %+v", info)
	}
	roundtrip(t, app, echo, info.TunnelIPv6.Addr().AsSlice(), []byte("IPv6 through IPv6"))
}

func TestDataRekeyOpenVPN26(t *testing.T) {
	binaryPath := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, binaryPath, pki)
	for _, test := range []struct {
		name    string
		network string
		mode    string
		reneg   string
		first   int32
		rounds  int
	}{
		{"server-initiated", "udp", "v2-cookie", "2", 1, 1},
		{"client-initiated-rollover", "tcp", "tls-auth", "300", 2, 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			port, echo := startDataPeer(t, f, test.network, test.mode, true, "1.3", "AES-256-GCM",
				"--reneg-sec", test.reneg, "--auth-gen-token", "120", "120")
			cfg := f.config(pki, test.network, test.mode, port, true)
			if test.first == 2 {
				cfg.RekeyInterval = time.Second
			}
			var observer rekeyObserver
			cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, network, address string) (transport.PacketConn, error) {
				c, err := (transport.SocketDialer{}).DialPacket(ctx, network, address)
				if err != nil {
					return nil, err
				}
				observer.PacketConn = c
				return &observer, nil
			})
			c, app := connectData(t, cfg)
			info, ok := c.ControlInfo()
			if !ok || info.KeyID != 0 || !info.TunnelIP.Is4() {
				t.Fatalf("initial negotiation = %+v", info)
			}
			for i := 0; i <= test.rounds; i++ {
				if i != 0 {
					want := uint8((i-1)%7 + 1)
					waitForKeyID(t, c, want)
				}
				roundtrip(t, app, echo, info.TunnelIP.AsSlice(), []byte("packet through generation "+strconv.Itoa(i)))
			}
			if first := observer.first.Load(); first != test.first {
				t.Fatalf("rekey initiator = %d; want %d (1 peer, 2 client)", first, test.first)
			}
		})
	}
}

func interopPeer(t *testing.T) string {
	t.Helper()
	path := os.Getenv("OPENVPN_INTEROP_BIN")
	if path == "" {
		t.Skip("set OPENVPN_INTEROP_BIN to a pinned OpenVPN 2.6 test binary")
	}
	version := os.Getenv("OPENVPN_INTEROP_VERSION")
	switch version {
	case "":
		version = "2.6.23"
	case "2.6.22", "2.6.23":
	default:
		t.Fatal("unsupported reference peer version")
	}
	output, err := exec.CommandContext(t.Context(), path, "--version").Output()
	if err != nil || !bytes.HasPrefix(output, []byte("OpenVPN "+version+" ")) {
		t.Fatalf("expected OpenVPN %s: %v", version, err)
	}
	return path
}

func startDataPeer(t *testing.T, f fixture, network, mode string, auth bool, version, cipher string, extra ...string) (uint16, *net.UDPConn) {
	t.Helper()
	args := []string{
		"--dev", dataDevice, "--tls-version-min", version, "--tls-version-max", version, "--data-ciphers", cipher,
		"--keepalive", "1", "15", "--verb", "3",
	}
	port := f.start(t, network, mode, auth, append(args, extra...)...)
	configureTestLink(t, "10.49.0.1/24")
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 49, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return port, listener
}

func configureTestLink(t *testing.T, address string, flags ...string) {
	t.Helper()
	configureLink(t, dataDevice, address, flags...)
}

func configureLink(t *testing.T, device, address string, flags ...string) {
	t.Helper()
	for _, command := range [][]string{
		append([]string{"address", "add", address, "dev", device}, flags...),
		{"link", "set", "dev", device, "up"},
	} {
		if output, err := exec.CommandContext(t.Context(), "ip", command...).CombinedOutput(); err != nil {
			t.Fatalf("prepare isolated server TUN: %v: %s", err, output)
		}
	}
}

func connectData(t *testing.T, cfg client.Config) (*client.Client, transport.PacketConn) {
	t.Helper()
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	device, app := testkit.PacketPipe(8, transport.DefaultPacketSize)
	t.Cleanup(func() { device.Close() })
	t.Cleanup(func() { app.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	running := make(chan error, 1)
	go func() { running <- c.Run(ctx, device) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-running:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not terminate on cancellation")
		}
	})
	return c, app
}

func roundtrip(t *testing.T, app transport.PacketConn, echo *net.UDPConn, source, payload []byte) {
	t.Helper()
	if len(source) != 4 && len(source) != 16 {
		t.Fatalf("expected an assigned IP address, got %v", source)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	if err := echo.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	const sourcePort = 26617
	dest := echo.LocalAddr().(*net.UDPAddr)
	ipLen, protoIndex, addrOffset := 20, 9, 12
	ip := dest.IP.To4()
	var packet []byte
	if len(source) == 16 {
		ipLen, protoIndex, addrOffset = 40, 6, 8
		ip = dest.IP.To16()
		packet = ipv6UDP(source, ip, sourcePort, uint16(dest.Port), payload)
	} else {
		packet = ipv4UDP(source, ip, sourcePort, uint16(dest.Port), payload)
	}
	if err := app.WritePacket(ctx, packet); err != nil {
		t.Fatal(err)
	}
	var buffer [2048]byte
	n, remote, err := echo.ReadFromUDP(buffer[:])
	if err != nil {
		t.Fatalf("client-to-server tunnel packet: %v", err)
	}
	remoteIP := remote.IP.To4()
	if len(source) == 16 {
		remoteIP = remote.IP.To16()
	}
	if !bytes.Equal(buffer[:n], payload) || !bytes.Equal(remoteIP, source) || remote.Port != sourcePort {
		t.Fatalf("UDP request: %q from %v; expected %q from %v:%d", buffer[:n], remote, payload, source, sourcePort)
	}
	response := append([]byte("response: "), payload...)
	if _, err := echo.WriteToUDP(response, remote); err != nil {
		t.Fatal(err)
	}
	for {
		n, err := app.ReadPacket(ctx, buffer[:])
		if err != nil {
			t.Fatalf("server-to-client tunnel packet: %v", err)
		}
		if n < ipLen+8 || buffer[protoIndex] != 17 || !bytes.Equal(buffer[addrOffset:addrOffset+len(ip)], ip) ||
			!bytes.Equal(buffer[addrOffset+len(ip):addrOffset+2*len(ip)], source) ||
			binary.BigEndian.Uint16(buffer[ipLen+2:ipLen+4]) != sourcePort {
			// The server kernel may send other valid packets, such as an
			// IPv6 router solicitation, through this interface.
			continue
		}
		if !bytes.Equal(buffer[ipLen+8:n], response) {
			t.Fatalf("unexpected UDP payload through the tunnel: %q", buffer[ipLen+8:n])
		}
		return
	}
}

func ipv4UDP(src, dst []byte, sport, dport uint16, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], src)
	copy(packet[16:20], dst)
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20], 0))
	binary.BigEndian.PutUint16(packet[20:22], sport)
	binary.BigEndian.PutUint16(packet[22:24], dport)
	binary.BigEndian.PutUint16(packet[24:26], uint16(len(packet)-20))
	copy(packet[28:], payload)
	return packet
}

func ipv6UDP(src, dst []byte, sport, dport uint16, payload []byte) []byte {
	packet := make([]byte, 48+len(payload))
	packet[0], packet[6], packet[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	copy(packet[8:24], src)
	copy(packet[24:40], dst)
	binary.BigEndian.PutUint16(packet[40:42], sport)
	binary.BigEndian.PutUint16(packet[42:44], dport)
	binary.BigEndian.PutUint16(packet[44:46], uint16(len(packet)-40))
	copy(packet[48:], payload)
	sum := checksum(packet[8:], uint32(len(packet)-40)+17)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(packet[46:48], sum)
	return packet
}

func checksum(payload []byte, sum uint32) uint16 {
	for len(payload) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
	}
	if len(payload) == 1 {
		sum += uint32(payload[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func waitForKeyID(t *testing.T, c *client.Client, want uint8) {
	t.Helper()
	until := time.Now().Add(8 * time.Second)
	for time.Now().Before(until) {
		info, ok := c.ControlInfo()
		if !ok {
			t.Fatalf("session closed while waiting for key ID %d", want)
		}
		if info.KeyID == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	info, _ := c.ControlInfo()
	t.Fatalf("timed out waiting for key ID %d; current ID is %d", want, info.KeyID)
}

type rekeyObserver struct {
	transport.PacketConn
	first atomic.Int32
}

func (o *rekeyObserver) ReadPacket(ctx context.Context, buffer []byte) (int, error) {
	n, err := o.PacketConn.ReadPacket(ctx, buffer)
	if err == nil && n > 0 && wire.Opcode(buffer[0]>>3) == wire.SoftReset {
		o.first.CompareAndSwap(0, 1)
	}
	return n, err
}

func (o *rekeyObserver) WritePacket(ctx context.Context, packet []byte) error {
	if len(packet) > 0 && wire.Opcode(packet[0]>>3) == wire.SoftReset {
		o.first.CompareAndSwap(0, 2)
	}
	return o.PacketConn.WritePacket(ctx, packet)
}
