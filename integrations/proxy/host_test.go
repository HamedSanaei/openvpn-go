package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/transport"
)

func TestMaxAbsoluteProxyDNSName(t *testing.T) {
	label := strings.Repeat("a", 63)
	full := strings.Join([]string{label, label, label, strings.Repeat("b", 61)}, ".")
	for _, host := range []string{full, full + "."} {
		address := net.JoinHostPort(host, "443")
		got, port, err := splitTarget(address)
		if _, configErr := (client.Endpoint{Host: host}).Validated(); configErr != nil || err != nil || got != host || port != 443 {
			t.Fatalf("valid hostname was rejected: %v, %v", err, configErr)
		}
		if _, err := HTTPConnect(Config{Address: address}); err != nil {
			t.Fatal("valid proxy endpoint was rejected")
		}
		for _, entry := range []struct {
			create func(Config) (transport.Dialer, error)
			socks  bool
		}{{HTTPConnect, false}, {SOCKS5, true}} {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			observed := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					observed <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				if !entry.socks {
					req, err := http.ReadRequest(bufio.NewReader(conn))
					if err != nil || req.Host != address {
						observed <- errors.New("CONNECT authority did not preserve hostname")
						return
					}
					_, err = io.WriteString(conn, "HTTP/1.1 200 Connected\r\n\r\n")
					observed <- err
					return
				}
				if _, err = io.ReadFull(conn, make([]byte, 3)); err == nil {
					_, err = conn.Write([]byte{5, 0})
				}
				if err == nil {
					want := append(append([]byte{5, 1, 0, 3, byte(len(host))}, host...), 1, 187)
					got := make([]byte, len(want))
					if _, err = io.ReadFull(conn, got); err == nil && !bytes.Equal(want, got) {
						err = errors.New("SOCKS5 destination did not preserve hostname")
					}
				}
				if err == nil {
					_, err = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
				}
				observed <- err
			}()
			dialer, err := entry.create(Config{Address: ln.Addr().String(), Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := dialer.DialPacket(t.Context(), "tcp", address)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if err := <-observed; err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, host := range []string{full + "b.", label + "a.example", "one..example", full + ".."} {
		address := net.JoinHostPort(host, "443")
		if _, _, err := splitTarget(address); err != ErrProxy {
			t.Fatal("invalid DNS destination accepted")
		}
		if _, err := SOCKS5(Config{Address: address}); err != ErrProxy {
			t.Fatal("invalid DNS proxy address accepted")
		}
	}
}
