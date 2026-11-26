package tlscontrol

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestVerifiedTLSIdentityAndValidity(t *testing.T) {
	pki := testkit.NewPKI(t)
	identity, err := tls.X509KeyPair(pki.Server.Certificate, pki.Server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		host string
		now  time.Time
		fail bool
	}{
		{"dns", testkit.TestServerName, time.Now(), false},
		{"ip", "127.0.0.1", time.Now(), false},
		{"wrong_dns", "other.example.test", time.Now(), true},
		{"expired", testkit.TestServerName, time.Now().Add(2 * time.Hour), true},
		{"not_yet_valid", testkit.TestServerName, time.Now().Add(-2 * time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := ClientConfig(pki.CA, pki.Client.Certificate, pki.Client.PrivateKey, false)
			if err != nil {
				t.Fatal(err)
			}
			config.ServerName = tc.host
			config.Time = func() time.Time { return tc.now }
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var dialer net.Dialer
			local, err := dialer.DialContext(ctx, "tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			server := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{identity}, MaxVersion: tls.VersionTLS12})
			done := make(chan error, 1)
			go func() { done <- server.HandshakeContext(ctx) }()
			err = tls.Client(local, config).HandshakeContext(ctx)
			serverError := <-done
			if tc.fail {
				var verify *tls.CertificateVerificationError
				if !errors.As(err, &verify) {
					t.Fatalf("TLS handshake error = %v; want certificate failure", err)
				}
			} else if err != nil || serverError != nil {
				t.Fatalf("TLS handshake failed: client %v, server %v", err, serverError)
			}
		})
	}
}

func TestRejectIncompleteTLSConfiguration(t *testing.T) {
	pki := testkit.NewPKI(t)
	other := testkit.NewPKI(t)
	for _, tc := range []struct {
		root, cert, key []byte
	}{
		{nil, pki.Client.Certificate, pki.Client.PrivateKey},
		{[]byte("bad CA input"), pki.Client.Certificate, pki.Client.PrivateKey},
		{pki.CA, pki.Client.Certificate, nil},
		{pki.CA, pki.Client.Certificate, other.Client.PrivateKey},
	} {
		if _, err := ClientConfig(tc.root, tc.cert, tc.key, false); !errors.Is(err, ErrConfig) {
			t.Fatalf("invalid configuration error = %v", err)
		}
	}
}

func TestPushRequiresCompleteAndAllowedNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name string
		push string
		want error
	}{
		{"complete", "PUSH_REPLY,peer-id 13,key-derivation tls-ekm,cipher AES-256-GCM", nil},
		{"no_exporter", "PUSH_REPLY,peer-id 13,cipher AES-256-GCM", ErrNegotiation},
		{"no_peer", "PUSH_REPLY,key-derivation tls-ekm,cipher AES-256-GCM", ErrNegotiation},
		{"reserved_peer", "PUSH_REPLY,peer-id 16777215,key-derivation tls-ekm,cipher AES-256-GCM", ErrNegotiation},
		{"legacy_cipher", "PUSH_REPLY,peer-id 13,key-derivation tls-ekm,cipher AES-256-CBC", ErrNegotiation},
		{"duplicate_cipher", "PUSH_REPLY,peer-id 13,key-derivation tls-ekm,cipher AES-256-GCM,cipher AES-256-GCM", ErrNegotiation},
		{"compression", "PUSH_REPLY,peer-id 13,key-derivation tls-ekm,cipher AES-256-GCM,compress lz4", ErrNegotiation},
		{"script", "PUSH_REPLY,peer-id 13,key-derivation tls-ekm,cipher AES-256-GCM,up test-command", ErrNegotiation},
		{"invalid_continuation", "PUSH_REPLY,peer-id 13,key-derivation tls-ekm,cipher AES-256-GCM,push-continuation 1", ErrNegotiation},
		{"auth_failed", "AUTH_FAILED,synthetic secret", ErrAuth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pushState{allowed: []string{"AES-256-GCM"}}
			complete, err := p.add([]byte(tc.push))
			if !errors.Is(err, tc.want) || complete != (tc.want == nil) {
				t.Fatalf("push completion = %v, %v; want %v", complete, err, tc.want)
			}
		})
	}

	p := pushState{allowed: []string{"AES-256-GCM"}}
	if done, err := p.add([]byte("PUSH_REPLY,ifconfig 10.0.0.2 255.255.255.0,peer-id 13,push-continuation 2")); done || err != nil {
		t.Fatalf("initial push continuation = %v, %v", done, err)
	}
	if done, err := p.add([]byte("PUSH_REPLY,protocol-flags tls-ekm,cipher AES-256-GCM,push-continuation 1")); !done || err != nil || p.PeerID != 13 {
		t.Fatalf("final push continuation = %v, %v, id %d", done, err, p.PeerID)
	}
}
