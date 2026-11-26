// Package proxy provides explicit TCP proxy dialers for OpenVPN.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hamedsanaei/openvpn-go/transport"
)

var ErrProxy = errors.New("OpenVPN proxy negotiation failed")

// Config identifies a proxy. TLS enables verified TLS to the proxy itself.
// Credentials require TLS and are scoped to the proxy.
type Config struct {
	Address            string
	TLS                *tls.Config
	Username, Password string
	Timeout            time.Duration
	MaxPacketSize      int
}

// HTTPConnect uses the HTTP/1.1 CONNECT method for TCP endpoints.
func HTTPConnect(c Config) (transport.Dialer, error) { return newDialer(c, connectHTTP) }

// SOCKS5 uses the SOCKS5 CONNECT command for TCP endpoints.
func SOCKS5(c Config) (transport.Dialer, error) { return newDialer(c, connectSOCKS) }

func newDialer(c Config, negotiate func(net.Conn, string, string, uint16, Config) (net.Conn, error)) (transport.Dialer, error) {
	host, _, err := splitTarget(c.Address)
	if err != nil || c.Timeout < 0 || c.Timeout > time.Minute ||
		c.MaxPacketSize < 0 || c.MaxPacketSize > transport.MaxPacketSize ||
		(c.Username == "") != (c.Password == "") || len(c.Username) > 255 || len(c.Password) > 255 ||
		c.Username != "" && c.TLS == nil {
		return nil, ErrProxy
	}
	if c.TLS != nil {
		if c.TLS.InsecureSkipVerify {
			return nil, ErrProxy
		}
		c.TLS = c.TLS.Clone()
		if c.TLS.ServerName == "" {
			c.TLS.ServerName = host
		}
		c.TLS.NextProtos = nil
		c.TLS.MinVersion = max(tls.VersionTLS12, c.TLS.MinVersion)
		if c.TLS.MaxVersion != 0 && c.TLS.MaxVersion < c.TLS.MinVersion {
			return nil, ErrProxy
		}
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	return (transport.SocketDialer{MaxPacketSize: c.MaxPacketSize}).WithDialContext(func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, transport.ErrUnsupportedNetwork
		}
		host, port, err := splitTarget(address)
		if err != nil {
			return nil, err
		}
		ip, _ := netip.ParseAddr(host)
		if network == "tcp4" && !ip.Unmap().Is4() || network == "tcp6" && !ip.Unmap().Is6() {
			return nil, ErrProxy
		}
		ctx, cancel := context.WithTimeout(ctx, c.Timeout)
		defer cancel()
		var dial net.Dialer
		raw, err := dial.DialContext(ctx, "tcp", c.Address)
		if err != nil {
			return nil, proxyError(ctx)
		}
		deadline, _ := ctx.Deadline()
		if err := raw.SetDeadline(deadline); err != nil {
			raw.Close()
			return nil, proxyError(ctx)
		}
		interrupted := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			raw.Close()
			close(interrupted)
		})
		var conn net.Conn = raw
		if c.TLS != nil {
			secured := tls.Client(raw, c.TLS)
			err = secured.HandshakeContext(ctx)
			conn = secured
		}
		if err == nil {
			conn, err = negotiate(conn, address, host, port, c)
		}
		if !stop() {
			<-interrupted
		}
		if err != nil || ctx.Err() != nil || raw.SetDeadline(time.Time{}) != nil {
			raw.Close()
			return nil, proxyError(ctx)
		}
		return conn, nil
	}), nil
}

func proxyError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return ErrProxy
}

func splitTarget(address string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(address)
	n, parseErr := strconv.ParseUint(port, 10, 16)
	if err != nil || parseErr != nil || n == 0 || host == "" || len(host) > 253 {
		return "", 0, ErrProxy
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return host, uint16(n), nil
	}
	for label := range strings.SplitSeq(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", 0, ErrProxy
		}
		for _, r := range label {
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
				return "", 0, ErrProxy
			}
		}
	}
	return host, uint16(n), nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func connectHTTP(conn net.Conn, address, _ string, _ uint16, c Config) (net.Conn, error) {
	if strings.ContainsRune(c.Username, ':') {
		return nil, ErrProxy
	}
	request := "CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n"
	if c.Username != "" {
		request += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)) + "\r\n"
	}
	if _, err := io.Copy(conn, strings.NewReader(request+"\r\n")); err != nil {
		return nil, err
	}
	limit := &io.LimitedReader{R: conn, N: 16 << 10}
	reader := bufio.NewReaderSize(limit, 1024)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, ErrProxy
	}
	// CONNECT switches to a byte stream. Ignore response body metadata
	// and preserve bytes already buffered by the HTTP parser.
	limit.N = math.MaxInt64
	return bufferedConn{conn, reader}, nil
}

func connectSOCKS(conn net.Conn, _ string, host string, port uint16, c Config) (net.Conn, error) {
	method := byte(0)
	if c.Username != "" {
		method = 2
	}
	var pair [2]byte
	if _, err := conn.Write([]byte{5, 1, method}); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, pair[:]); err != nil || pair != [2]byte{5, method} {
		return nil, ErrProxy
	}
	if method == 2 {
		frame := append([]byte{1, byte(len(c.Username))}, c.Username...)
		frame = append(frame, byte(len(c.Password)))
		frame = append(frame, c.Password...)
		_, err := conn.Write(frame)
		clear(frame)
		if err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(conn, pair[:]); err != nil || pair != [2]byte{1, 0} {
			return nil, ErrProxy
		}
	}
	request := []byte{5, 1, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		kind := byte(1)
		if ip.Is6() {
			kind = 4
		}
		request = append(append(request, kind), ip.AsSlice()...)
	} else {
		request = append(append(request, 3, byte(len(host))), host...)
	}
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return nil, ErrProxy
	}
	var size int
	switch reply[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		if _, err := io.ReadFull(conn, pair[:1]); err != nil || pair[0] == 0 {
			return nil, ErrProxy
		}
		size = int(pair[0])
	default:
		return nil, ErrProxy
	}
	var bound [257]byte
	if _, err := io.ReadFull(conn, bound[:size+2]); err != nil {
		return nil, err
	}
	return conn, nil
}
