package testkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestServerName is the DNS SAN in certificates minted for the interop tests.
const TestServerName = "vpn.example.test"

// Identity contains a synthetic PEM certificate and private key.
type Identity struct {
	Certificate []byte
	PrivateKey  []byte
}

// PKI contains a synthetic CA and the identities signed by it.
type PKI struct {
	CA     []byte
	Server Identity
	Client Identity
}

func NewPKI(t testing.TB) PKI {
	t.Helper()
	rootKey := key(t)
	root := certificate(1, "Test OpenVPN CA")
	root.IsCA = true
	root.BasicConstraintsValid = true
	root.KeyUsage = x509.KeyUsageCertSign

	ca := sign(t, root, root, rootKey, rootKey)
	server := certificate(2, TestServerName)
	server.KeyUsage = x509.KeyUsageDigitalSignature
	server.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	server.DNSNames = []string{TestServerName}
	server.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}

	client := certificate(3, "OpenVPN test client")
	client.KeyUsage = x509.KeyUsageDigitalSignature
	client.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	return PKI{
		CA:     ca.Certificate,
		Server: sign(t, server, root, key(t), rootKey),
		Client: sign(t, client, root, key(t), rootKey),
	}
}

func certificate(serial int64, name string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
}

func key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func sign(t testing.TB, template, parent *x509.Certificate, subject, signer *ecdsa.PrivateKey) Identity {
	t.Helper()
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, &subject.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(subject)
	if err != nil {
		t.Fatal(err)
	}
	return Identity{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
	}
}
