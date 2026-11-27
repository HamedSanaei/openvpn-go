package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

func TestProxyTCPAdapters(t *testing.T) {
	pki := testkit.NewPKI(t)
	identity, err := tls.X509KeyPair(pki.Server.Certificate, pki.Server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pki.CA)
	for _, tc := range []struct {
		name  string
		dial  func(Config) (transport.Dialer, error)
		serve func(net.Conn) error
	}{
		{"https-connect", HTTPConnect, func(conn net.Conn) error {
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil || req.Method != http.MethodConnect || req.Host != "peer.example.test:443" ||
				req.Header.Get("Proxy-Authorization") != "Basic dXNlcjpzZWNyZXQ=" {
				return errors.New("invalid proxy CONNECT request")
			}
			_, err = conn.Write([]byte("HTTP/1.1 103 Early Hints\r\nLink: </hint>\r\n\r\n" +
				"HTTP/1.1 200 Connected\r\nContent-Length: unknown\r\nTransfer-Encoding: arbitrary\r\n\r\n\x00\x02ok"))
			return err
		}},
		{"socks5", SOCKS5, func(conn net.Conn) error {
			var header [64]byte
			if _, err := io.ReadFull(conn, header[:3]); err != nil || !bytes.Equal(header[:3], []byte{5, 1, 2}) {
				return errors.New("invalid method offer")
			}
			if _, err := conn.Write([]byte{5, 2}); err != nil {
				return err
			}
			if _, err := io.ReadFull(conn, header[:13]); err != nil || string(header[:13]) != "\x01\x04user\x06secret" {
				return errors.New("invalid proxy credentials")
			}
			if _, err := conn.Write([]byte{1, 0}); err != nil {
				return err
			}
			host := "peer.example.test"
			want := append(append([]byte{5, 1, 0, 3, byte(len(host))}, host...), 1, 187)
			if _, err := io.ReadFull(conn, header[:len(want)]); err != nil || !bytes.Equal(header[:len(want)], want) {
				return errors.New("invalid proxy destination")
			}
			_, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1, 0, 2, 'o', 'k'})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{identity}})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(4 * time.Second))
				done <- tc.serve(conn)
			}()
			d, err := tc.dial(Config{Address: ln.Addr().String(), TLS: &tls.Config{RootCAs: roots},
				Username: "user", Password: "secret", Timeout: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.DialPacket(t.Context(), "tcp", "peer.example.test:443")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var received [8]byte
			if n, err := conn.ReadPacket(t.Context(), received[:]); err != nil || string(received[:n]) != "ok" {
				t.Fatalf("read after negotiation: %d %v", n, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, err := d.DialPacket(t.Context(), "udp", "peer.example.test:443"); err != transport.ErrUnsupportedNetwork {
				t.Fatalf("UDP over a stream proxy: %v", err)
			}
			if _, err := d.DialPacket(t.Context(), "tcp4", "peer.example.test:443"); err != ErrProxy {
				t.Fatalf("proxy-resolved DNS ignored an explicit address family: %v", err)
			}
		})
	}
}

func TestProxyFailureAndCancellationAreRedacted(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		enter := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := ln.Accept()
			if err != nil {
				close(enter)
				return
			}
			defer conn.Close()
			request := bufio.NewReader(conn)
			if _, err := http.ReadRequest(request); err != nil {
				close(enter)
				return
			}
			close(enter)
			if timeout {
				io.Copy(io.Discard, request)
				return
			}
			io.WriteString(conn, "HTTP/1.1 407 secret-proxy-response\r\n\r\n")
		}()
		d, err := HTTPConnect(Config{Address: ln.Addr().String(), Timeout: time.Second})
		if err != nil {
			ln.Close()
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		if timeout {
			go func() { <-enter; cancel() }()
		}
		conn, err := d.DialPacket(ctx, "tcp", "peer.example.test:443")
		cancel()
		ln.Close()
		<-done
		want := ErrProxy
		if timeout {
			want = context.Canceled
		}
		if conn != nil || !errors.Is(err, want) || strings.Contains(err.Error(), "secret-proxy-response") {
			t.Fatalf("result %v, want %v", err, want)
		}
	}
	if _, err := HTTPConnect(Config{Address: "localhost:8080", Username: "u", Password: "p"}); err != ErrProxy {
		t.Fatal("credentials permitted on cleartext proxy hop")
	}
}

func TestTLSProxyTrustFailureIsRedacted(t *testing.T) {
	pki := testkit.NewPKI(t)
	identity, err := tls.X509KeyPair(pki.Server.Certificate, pki.Server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	trusted := x509.NewCertPool()
	trusted.AppendCertsFromPEM(pki.CA)
	for _, create := range []func(Config) (transport.Dialer, error){HTTPConnect, SOCKS5} {
		for _, config := range []*tls.Config{
			{RootCAs: x509.NewCertPool()},
			{RootCAs: trusted, ServerName: "private.invalid"},
			{RootCAs: trusted, Time: func() time.Time { return time.Now().Add(2 * time.Hour) }},
		} {
			ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{identity}})
			if err != nil {
				t.Fatal(err)
			}
			serverRead := make(chan int, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					serverRead <- -1
					return
				}
				defer conn.Close()
				var buf [1]byte
				n, _ := conn.Read(buf[:])
				serverRead <- n
			}()
			dialer, err := create(Config{Address: ln.Addr().String(), TLS: config, Username: "test-user", Password: "test-password"})
			if err != nil {
				ln.Close()
				t.Fatal(err)
			}
			_, err = dialer.DialPacket(t.Context(), "tcp", "vpn.example.test:443")
			ln.Close()
			if !errors.Is(err, ErrProxy) || !errors.Is(err, transport.ErrPeerCertificate) ||
				strings.Contains(err.Error(), "private.invalid") || strings.Contains(err.Error(), "127.0.0.1") {
				t.Fatalf("unexpected proxy error: %v", err)
			}
			if n := <-serverRead; n != 0 {
				t.Fatal("application bytes reached an unverified proxy")
			}
		}
	}
}
