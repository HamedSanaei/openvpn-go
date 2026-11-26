//go:build linux

package interop_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/integrations/proxy"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestHTTPProxyRetainsVPNIdentity(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	fixture := makePKIFixture(t, binary, pki)
	port := fixture.start(t, "tcp", "tls", false)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	for _, wrong := range []bool{false, true} {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		proxyErr := make(chan error, 1)
		go func() {
			local, err := ln.Accept()
			if err != nil {
				proxyErr <- err
				return
			}
			defer local.Close()
			local.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(local)
			request, err := http.ReadRequest(reader)
			if err != nil || request.Method != http.MethodConnect || request.Host != address {
				proxyErr <- errors.New("invalid local CONNECT destination")
				return
			}
			upstream, err := net.DialTimeout("tcp4", address, time.Second)
			if err != nil {
				proxyErr <- err
				return
			}
			defer upstream.Close()
			upstream.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(local, "HTTP/1.1 200 Connected\r\n\r\n"); err != nil {
				proxyErr <- err
				return
			}
			done := make(chan struct{})
			go func() {
				io.Copy(upstream, reader)
				upstream.(*net.TCPConn).CloseWrite()
				close(done)
			}()
			io.Copy(local, upstream)
			local.(*net.TCPConn).CloseWrite()
			<-done
			proxyErr <- nil
		}()
		cfg := fixture.config(pki, "tcp", "tls", port, false)
		cfg.Dialer, err = proxy.HTTPConnect(proxy.Config{Address: ln.Addr().String()})
		if err != nil {
			t.Fatal(err)
		}
		if wrong {
			cfg.Endpoints[0].ServerName = "wrong.example.test"
		}
		c, err := client.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		err = c.Connect(t.Context())
		c.Close()
		ln.Close()
		if proxyFailure := <-proxyErr; proxyFailure != nil {
			t.Fatal(proxyFailure)
		}
		var failure *client.Error
		if wrong && (!errors.As(err, &failure) || failure.Code != client.CodeCertificate) || !wrong && err != nil {
			t.Fatalf("proxy endpoint verification: wrong=%v, result=%v", wrong, err)
		}
	}
}
