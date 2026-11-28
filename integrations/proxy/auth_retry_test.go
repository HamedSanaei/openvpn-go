package proxy

import (
	"bufio"
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

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

func TestProxyAuthenticationStopsRetryAfterExplicitRejection(t *testing.T) {
	pki := testkit.NewPKI(t)
	key, err := tls.X509KeyPair(pki.Server.Certificate, pki.Server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pki.CA)
	for _, tc := range []struct {
		name   string
		create func(Config) (transport.Dialer, error)
		reject func(net.Conn) error
	}{
		{"http", HTTPConnect, func(conn net.Conn) error {
			if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
				return err
			}
			_, err := io.WriteString(conn, "HTTP/1.1 407 synthetic-private-reason\r\nProxy-Authenticate: Basic\r\n\r\n")
			return err
		}},
		{"socks", SOCKS5, func(conn net.Conn) error {
			if _, err := io.ReadFull(conn, make([]byte, 3)); err != nil {
				return err
			}
			if _, err := conn.Write([]byte{5, 2}); err != nil {
				return err
			}
			if _, err := io.ReadFull(conn, make([]byte, 3+len("fixture")+len("synthetic"))); err != nil {
				return err
			}
			_, err := conn.Write([]byte{1, 1})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{key}})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			replies := make(chan error, 2)
			go func() {
				for i := range 2 {
					conn, err := ln.Accept()
					if err == nil && i != 0 {
						conn.SetDeadline(time.Now().Add(time.Second))
						err = tc.reject(conn)
					}
					if conn != nil {
						conn.Close()
					}
					replies <- err
				}
			}()
			dialer, err := tc.create(Config{Address: ln.Addr().String(), TLS: &tls.Config{RootCAs: roots},
				Username: "fixture", Password: "synthetic"})
			if err != nil {
				t.Fatal(err)
			}
			c, err := client.New(client.Config{
				TLS:       &client.TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey},
				Endpoints: []client.Endpoint{{Host: "vpn.example.test", Network: "tcp"}},
				Dialer:    dialer, Retry: client.RetryPolicy{MaxAttempts: client.UnlimitedAttempts, InitialBackoff: time.Millisecond},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			err = c.Connect(ctx)
			var failure *client.Error
			attempts := c.AttemptReports(0)
			if !errors.As(err, &failure) || failure.Code != client.CodeAuthentication ||
				len(attempts) != 2 || attempts[0].Code != client.CodeNetwork || attempts[1].Code != client.CodeAuthentication ||
				attempts[1].Stage != client.StageDial || strings.Contains(err.Error(), "synthetic-private") {
				t.Fatalf("proxy authentication = %v, attempts = %+v", err, attempts)
			}
			for range 2 {
				if err := <-replies; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
