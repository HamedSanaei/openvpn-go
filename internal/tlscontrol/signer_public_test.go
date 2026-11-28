package tlscontrol

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

type externalPublicSigner struct {
	crypto.Signer
	public crypto.PublicKey
	calls  *atomic.Int32
}

func (s externalPublicSigner) Public() crypto.PublicKey {
	s.calls.Add(1)
	return s.public
}

func TestExternalPublicKeysValidatedBeforeTLS(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pki := testkit.NewPKI(t)
	serverIdentity, err := tls.X509KeyPair(pki.Server.Certificate, pki.Server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pki.CA) {
		t.Fatal("missing test roots")
	}
	for _, cert := range []struct {
		name string
		key  crypto.Signer
		bad  []crypto.PublicKey
	}{
		{"RSA", rsaKey, []crypto.PublicKey{(*rsa.PublicKey)(nil), &rsa.PublicKey{E: 65537}, ecKey.Public()}},
		{"ECDSA", ecKey, []crypto.PublicKey{(*ecdsa.PublicKey)(nil), &ecdsa.PublicKey{Curve: elliptic.P256()},
			&ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, rsaKey.Public()}},
		{"Ed25519", edKey, []crypto.PublicKey{ed25519.PublicKey(nil), ed25519.PublicKey{1}, ecKey.Public()}},
	} {
		t.Run(cert.name, func(t *testing.T) {
			template := &x509.Certificate{SerialNumber: big.NewInt(4), NotBefore: time.Now().Add(-time.Hour),
				NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			raw, err := x509.CreateCertificate(rand.Reader, template, template, cert.key.Public(), cert.key)
			if err != nil {
				t.Fatal(err)
			}
			leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
			run := func(public crypto.PublicKey, dynamic, valid bool) {
				t.Helper()
				var calls atomic.Int32
				key := externalPublicSigner{cert.key, public, &calls}
				config := &tls.Config{RootCAs: roots, ServerName: testkit.TestServerName, MinVersion: tls.VersionTLS13}
				var setupErr error
				if dynamic {
					setupErr = SetKeyProvider(config, leaf, nil, func(context.Context) (crypto.Signer, error) { return key, nil })
				} else {
					setupErr = SetKeyProvider(config, leaf, key, nil)
				}
				if !valid && !dynamic {
					if setupErr != ErrConfig || calls.Load() != 1 {
						t.Fatalf("malformed static key = %v, calls=%d", setupErr, calls.Load())
					}
					return
				}
				if setupErr != nil {
					t.Fatal(setupErr)
				}
				clientRaw, serverRaw := net.Pipe()
				defer serverRaw.Close()
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				server := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{serverIdentity},
					ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13})
				done := make(chan error, 1)
				go func() { done <- server.HandshakeContext(ctx) }()
				session := tls.Client(clientRaw, config)
				err := session.HandshakeContext(ctx)
				clientRaw.Close()
				serverErr := <-done
				if valid {
					if err != nil || serverErr != nil {
						t.Fatalf("valid client signer was rejected: %v, %v", err, serverErr)
					}
				} else if !errors.Is(err, ErrAuth) {
					t.Fatalf("malformed dynamic key = %v", err)
				}
				if calls.Load() != 1 {
					t.Fatalf("external signer returned its key %d times", calls.Load())
				}
			}
			run(cert.key.Public(), false, true)
			run(cert.key.Public(), true, true)
			for _, bad := range cert.bad {
				run(bad, false, false)
				run(bad, true, false)
			}
		})
	}
}
