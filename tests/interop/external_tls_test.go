//go:build linux

package interop_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/integrations/proxy"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

// The optional public-chain fixture listens only on loopback and forwards
// CONNECT exclusively to the administrator-specified lab VPN endpoint.
func TestExternalTLSProxyProfile(t *testing.T) {
	path := os.Getenv("OVPN_EXTERNAL_PROFILE")
	certPath, keyPath := os.Getenv("OVPN_EXTERNAL_TLS_CERT"), os.Getenv("OVPN_EXTERNAL_TLS_KEY")
	name := os.Getenv("OVPN_EXTERNAL_TLS_NAME")
	target := os.Getenv("OVPN_EXTERNAL_TLS_TARGET")
	if certPath == "" && keyPath == "" {
		t.Skip("set authorized TLS fixture paths")
	}
	if path == "" || certPath == "" || keyPath == "" || name == "" || target == "" || os.Getenv("OVPN_EXTERNAL_ECHO") == "" {
		t.Fatal("incomplete external TLS fixture settings")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal("invalid TLS fixture key pair")
	}
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) {
			bind := "127.0.0.1:0"
			if family == "tcp6" {
				bind = "[::1]:0"
			}
			ln, err := tls.Listen(family, bind, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal("TLS fixture listener unavailable")
			}
			ctx, cancel := context.WithCancel(t.Context())
			var wg sync.WaitGroup
			var forwarded atomic.Int64
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					local, err := ln.Accept()
					if err != nil {
						return
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer local.Close()
						stop := context.AfterFunc(ctx, func() { local.Close() })
						defer stop()
						_ = local.SetDeadline(time.Now().Add(30 * time.Second))
						rd := bufio.NewReader(io.LimitReader(local, 1<<20))
						req, err := http.ReadRequest(rd)
						if err != nil || req.Method != http.MethodConnect || req.Host != target || req.RequestURI != target {
							return
						}
						upstream, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", target)
						if err != nil {
							return
						}
						defer upstream.Close()
						stopUp := context.AfterFunc(ctx, func() { upstream.Close() })
						defer stopUp()
						_ = upstream.SetDeadline(time.Now().Add(30 * time.Second))
						forwarded.Add(1)
						if _, err = io.WriteString(local, "HTTP/1.1 200 Connected\r\n\r\n"); err != nil {
							return
						}
						done := make(chan struct{})
						go func() { defer close(done); _, _ = io.Copy(upstream, rd); upstream.Close() }()
						_, _ = io.Copy(local, upstream)
						local.Close()
						upstream.Close()
						<-done
					}()
				}
			}()
			t.Cleanup(func() { cancel(); ln.Close(); wg.Wait() })
			for _, wrong := range []bool{true, false} {
				serverName := name
				if wrong {
					serverName = "untrusted.invalid"
				}
				dialer, err := proxy.HTTPConnect(proxy.Config{Address: ln.Addr().String(), TLS: &tls.Config{ServerName: serverName}})
				if err != nil {
					t.Fatal("TLS proxy configuration rejected")
				}
				if wrong {
					conn, err := dialer.DialPacket(ctx, "tcp", target)
					if conn != nil {
						conn.Close()
					}
					if !errors.Is(err, transport.ErrPeerCertificate) || forwarded.Load() != 0 {
						t.Fatal("wrong proxy name was not rejected before forwarding")
					}
					t.Log("wrong TLS proxy identity rejected before forwarding")
					continue
				}
				result := probeExternalProfileWithDialer(ctx, path, dialer)
				report, err := json.Marshal(result)
				if err != nil {
					t.Fatal("cannot encode redacted result")
				}
				t.Log(string(report))
				if result.Stage != "verified" || result.RoundTrips != 2 || forwarded.Load() != 2 {
					t.Fatal("TLS proxy traffic/reconnect qualification failed")
				}
			}
		})
	}
}

func externalControlEcho(ctx context.Context, app transport.PacketConn, info client.ControlInfo, target netip.Addr) error {
	if target.Is4() {
		return externalEcho(ctx, app, info.TunnelIP, target)
	}
	if info.Tunnel.BlockIPv6 || !info.TunnelIPv6.IsValid() {
		return errors.New("no usable IPv6 tunnel address")
	}
	return externalEcho6(ctx, app, info.TunnelIPv6.Addr(), target)
}

func externalEcho6(ctx context.Context, app transport.PacketConn, source, peer netip.Addr) error {
	if !source.Is6() || source.Is4In6() || !peer.Is6() || peer.Is4In6() {
		return errors.New("invalid IPv6 echo addresses")
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	src, dst := source.As16(), peer.As16()
	packet := make([]byte, 40+8+56)
	packet[0], packet[6], packet[7] = 0x60, 58, 64
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	copy(packet[8:24], src[:])
	copy(packet[24:40], dst[:])
	packet[40] = 128
	rand.Read(packet[44:])
	// Addresses and upper-layer payload are contiguous in this simple IPv6 packet.
	binary.BigEndian.PutUint16(packet[42:44], checksum(packet[8:], uint32(len(packet)-40)+58))
	buf := make([]byte, transport.DefaultPacketSize)
	for ctx.Err() == nil {
		round, stop := context.WithTimeout(ctx, 300*time.Millisecond)
		err := app.WritePacket(round, packet)
		if err == nil {
			for {
				n, e := app.ReadPacket(round, buf)
				if e != nil {
					err = e
					break
				}
				if n == len(packet) && buf[0]>>4 == 6 && buf[6] == 58 && buf[40] == 129 && buf[41] == 0 &&
					int(binary.BigEndian.Uint16(buf[4:6])) == n-40 && bytes.Equal(buf[8:24], dst[:]) && bytes.Equal(buf[24:40], src[:]) &&
					checksum(buf[8:n], uint32(n-40)+58) == 0 && bytes.Equal(buf[44:n], packet[44:]) {
					break
				}
			}
		}
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return ctx.Err()
}

// Validate the optional IPv6 probe independently of external server settings.
func TestExternalIPv6EchoHarness(t *testing.T) {
	a, b := testkit.PacketPipe(4, 1500)
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	src, dst := netip.MustParseAddr("fd49::2"), netip.MustParseAddr("fd49::1")
	cfg := client.ControlInfo{TunnelIPv6: netip.PrefixFrom(src, 64)}
	cfg.Tunnel.BlockIPv6 = true
	if err := externalControlEcho(ctx, a, cfg, dst); err == nil {
		t.Fatal("blocked IPv6 was probed")
	}
	cfg.Tunnel = tunnel.Configuration{}
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		n, err := b.ReadPacket(ctx, buf)
		if err != nil {
			done <- err
			return
		}
		if n != 104 || buf[0]>>4 != 6 || buf[6] != 58 || buf[40] != 128 || checksum(buf[8:n], uint32(n-40)+58) != 0 {
			done <- errors.New("bad ICMPv6 request")
			return
		}
		packet := buf[:n]
		s, d := src.As16(), dst.As16()
		if !bytes.Equal(packet[8:24], s[:]) || !bytes.Equal(packet[24:40], d[:]) {
			done <- errors.New("bad echo address")
			return
		}
		copy(packet[8:24], d[:])
		copy(packet[24:40], s[:])
		packet[40] = 129
		// A valid checksum with the wrong nonce must not satisfy the probe.
		packet[48] ^= 1
		binary.BigEndian.PutUint16(packet[42:44], 0)
		binary.BigEndian.PutUint16(packet[42:44], checksum(packet[8:], uint32(n-40)+58))
		if err := b.WritePacket(ctx, packet); err != nil {
			done <- err
			return
		}
		packet[48] ^= 1
		binary.BigEndian.PutUint16(packet[42:44], 0)
		binary.BigEndian.PutUint16(packet[42:44], checksum(packet[8:], uint32(n-40)+58))
		done <- b.WritePacket(ctx, packet)
	}()
	if err := externalControlEcho(ctx, a, cfg, dst); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
