//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
	"github.com/hamedsanaei/openvpn-go/transport"
)

const username = "interop-user"
const password = "interop-password"

func TestControlOpenVPN26(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	fixture := makeFixture(t, binary, pki)
	for _, network := range []string{"udp", "tcp"} {
		for _, mode := range []string{"tls", "tls-auth", "tls-crypt", "v2", "v2-cookie"} {
			for _, passwordAuth := range []bool{false, true} {
				name := network + "/" + mode + "/certificate"
				if passwordAuth {
					name += "-password"
				}
				t.Run(name, func(t *testing.T) {
					port := fixture.start(t, network, mode, passwordAuth)
					cfg := fixture.config(pki, network, mode, port, passwordAuth)
					info := connect(t, cfg)
					if info.TLSVersion != tls.VersionTLS12 || info.DataCipher != "AES-256-GCM" {
						t.Fatalf("unexpected negotiation: %+v", info)
					}
				})
			}
		}
	}
	t.Run("tls13", func(t *testing.T) {
		port := fixture.start(t, "tcp", "tls", false, "--tls-version-min", "1.3", "--tls-version-max", "1.3")
		if info := connect(t, fixture.config(pki, "tcp", "tls", port, false)); info.TLSVersion != tls.VersionTLS13 {
			t.Fatalf("TLS version = %x", info.TLSVersion)
		}
	})
	t.Run("loss_and_reordering", func(t *testing.T) {
		port := fixture.start(t, "udp", "tls", false, "--max-packet-size", "380")
		cfg := fixture.config(pki, "udp", "tls", port, false)
		var link *impairedUDP
		cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, network, address string) (transport.PacketConn, error) {
			conn, err := (transport.SocketDialer{}).DialPacket(ctx, network, address)
			if err != nil {
				return nil, err
			}
			link = &impairedUDP{PacketConn: conn}
			return link, nil
		})
		connect(t, cfg)
		if !link.dropped || !link.reordered || !link.released {
			t.Fatalf("impairment not exercised: drop=%v reorder=%v release=%v", link.dropped, link.reordered, link.released)
		}
	})

	t.Run("authentication", func(t *testing.T) {
		port := fixture.start(t, "tcp", "tls", true)
		other := testkit.NewPKI(t)
		for _, tc := range []struct {
			name string
			edit func(*client.Config)
			want client.ErrorCode
		}{
			{"wrong_name", func(cfg *client.Config) { cfg.Endpoints[0].ServerName = "wrong.example.test" }, client.CodeCertificate},
			{"wrong_ca", func(cfg *client.Config) { cfg.TLS.CA = other.CA }, client.CodeCertificate},
			{"wrong_password", func(cfg *client.Config) { cfg.Credentials.Password = "invalid-test-password" }, client.CodeAuthentication},
		} {
			t.Run(tc.name, func(t *testing.T) {
				cfg := fixture.config(pki, "tcp", "tls", port, true)
				tc.edit(&cfg)
				c, err := client.New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				err = c.Connect(t.Context())
				var typed *client.Error
				if !errors.As(err, &typed) || typed.Code != tc.want || strings.Contains(err.Error(), cfg.Credentials.Password) {
					t.Fatalf("Connect = %v; expected redacted %q", err, tc.want)
				}
				if _, ok := c.ActiveEndpoint(); ok {
					t.Fatal("an unauthenticated endpoint became active")
				}
			})
		}
	})
}

func connect(t *testing.T, cfg client.Config) client.ControlInfo {
	t.Helper()
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	info, ok := c.ControlInfo()
	if !ok || c.State() != client.StateConnected {
		t.Fatalf("Connect returned without an active negotiation: %s", c.State())
	}
	return info
}

type fixture struct {
	binary    string
	dir       string
	namespace string
}

func makeFixture(t *testing.T, binary string, pki testkit.PKI) fixture {
	t.Helper()
	f := fixture{binary: binary, dir: t.TempDir()}
	write := func(name string, data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(f.dir, name), data, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.pem", pki.CA, 0600)
	write("server.pem", pki.Server.Certificate, 0600)
	write("server.key", pki.Server.PrivateKey, 0600)
	write("verify-user", []byte("#!/bin/sh\n{ IFS= read -r user; IFS= read -r pass; } < \"$1\"\n[ \"$user\" = "+username+" ] && [ \"$pass\" = "+password+" ]\n"), 0700)
	for _, args := range [][]string{
		{"--genkey", "secret", "shared.key"},
		{"--genkey", "tls-crypt-v2-server", "wrap.key"},
		{"--tls-crypt-v2", "wrap.key", "--genkey", "tls-crypt-v2-client", "wrapped-client.pem", "b3BlbnZwbi1pbnRlcm9w"},
	} {
		cmd := exec.CommandContext(t.Context(), f.binary, args...)
		cmd.Dir = f.dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generate test key: %v\n%s", err, out)
		}
	}
	return f
}

func (f fixture) start(t *testing.T, network, mode string, passwordAuth bool, extra ...string) uint16 {
	t.Helper()
	port := localPort(t, network)
	f.launch(t, port, network, mode, passwordAuth, extra...)
	return port
}

func (f fixture) launch(t *testing.T, port uint16, network, mode string, passwordAuth bool, extra ...string) func() {
	t.Helper()
	proto := "udp4"
	if network == "tcp" {
		proto = "tcp4-server"
	}

	args := []string{
		"--dev", "tun", "--disable-dco", "--proto", proto,
		"--local", "127.0.0.1", "--port", strconv.Itoa(int(port)),
		"--server", "10.49.0.0", "255.255.255.0", "--topology", "subnet", "--ifconfig-noexec",
		"--route-noexec", "--ca", "ca.pem", "--cert", "server.pem", "--key", "server.key",
		"--dh", "none", "--data-ciphers", "AES-256-GCM",
		"--tls-version-min", "1.2", "--tls-version-max", "1.2",
		"--verb", "4",
	}
	switch mode {
	case "tls-auth":
		args = append(args, "--tls-auth", "shared.key", "0", "--auth", "SHA256")
	case "tls-crypt":
		args = append(args, "--tls-crypt", "shared.key")
	case "v2":
		args = append(args, "--tls-crypt-v2", "wrap.key", "allow-noncookie")
	case "v2-cookie":
		args = append(args, "--tls-crypt-v2", "wrap.key", "force-cookie")
	}
	if passwordAuth {
		args = append(args, "--script-security", "2", "--auth-user-pass-verify", "./verify-user", "via-file")
	}
	args = append(args, extra...)
	binary := f.binary
	if f.namespace != "" {
		args = append([]string{"netns", "exec", f.namespace, binary}, args...)
		binary = "ip"
	}
	cmd := exec.CommandContext(t.Context(), binary, args...)
	cmd.Dir = f.dir
	log, err := os.CreateTemp(f.dir, "server-log-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stop := sync.OnceFunc(func() {
		cmd.Process.Kill()
		<-done
	})
	t.Cleanup(func() {
		stop()
		if t.Failed() {
			output, _ := os.ReadFile(log.Name())
			t.Logf("OpenVPN server diagnostics:\n%s", output)
		}
	})

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		output, err := os.ReadFile(log.Name())
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(output, []byte("Initialization Sequence Completed")) {
			return stop
		}
		if bytes.Contains(output, []byte("Exiting due to fatal error")) {
			t.Fatal("OpenVPN exited during startup")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("OpenVPN server did not start")
	return nil
}

func localPort(t *testing.T, network string) uint16 {
	t.Helper()
	if network == "udp" {
		socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := socket.LocalAddr().(*net.UDPAddr).Port
		socket.Close()
		return uint16(port)
	}
	socket, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := socket.Addr().(*net.TCPAddr).Port
	socket.Close()
	return uint16(port)
}

func (f fixture) config(pki testkit.PKI, network, mode string, port uint16, passwordAuth bool) client.Config {
	cfg := client.Config{
		Endpoints:        []client.Endpoint{{Host: "127.0.0.1", Network: network + "4", Port: port, ServerName: testkit.TestServerName}},
		TLS:              &client.TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey},
		HandshakeTimeout: 8 * time.Second,
	}
	if passwordAuth {
		cfg.Credentials = &client.Credentials{Username: username, Password: password}
	}
	switch mode {
	case "tls-auth":
		cfg.Control = client.ControlProtection{Mode: client.ControlTLSAuth, Key: f.key("shared.key"), Digest: "SHA256", Direction: client.KeyDirection1}
	case "tls-crypt":
		cfg.Control = client.ControlProtection{Mode: client.ControlTLSCrypt, Key: f.key("shared.key")}
	case "v2", "v2-cookie":
		cfg.Control = client.ControlProtection{Mode: client.ControlTLSCryptV2, Key: f.key("wrapped-client.pem")}
	}
	return cfg
}

func (f fixture) key(name string) []byte {
	raw, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		panic(err)
	}
	return raw
}

type impairedUDP struct {
	transport.PacketConn
	dropped   bool
	reordered bool
	released  bool
	held      []byte
	heldID    uint32
}

func (l *impairedUDP) WritePacket(ctx context.Context, packet []byte) error {
	h, err := wire.ParseHeader(packet)
	if err == nil && h.Opcode == wire.ClientReset && !l.dropped {
		l.dropped = true
		return nil
	}
	return l.PacketConn.WritePacket(ctx, packet)
}

func (l *impairedUDP) ReadPacket(ctx context.Context, buffer []byte) (int, error) {
	if l.reordered && !l.released {
		l.released = true
		return copy(buffer, l.held), nil
	}
	for {
		n, err := l.PacketConn.ReadPacket(ctx, buffer)
		if err != nil || l.reordered || n < wire.PrefixSize {
			return n, err
		}
		p, err := wire.ParseControl(buffer[:wire.PrefixSize], buffer[wire.PrefixSize:n])
		if err != nil || p.Opcode != wire.Control {
			return n, nil
		}
		if l.held == nil {
			l.held, l.heldID = bytes.Clone(buffer[:n]), p.ID
			continue
		}
		if p.ID > l.heldID {
			l.reordered = true
			return n, nil
		}
	}
}
