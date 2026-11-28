package testkit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
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
	issuer *ecdsa.PrivateKey
}

func NewPKI(t testing.TB) PKI {
	return NewPKIWithServer(t, nil)
}

// NewPKIWithServer allows tests to change the server template before signing.
func NewPKIWithServer(t testing.TB, edit func(*x509.Certificate)) PKI {
	t.Helper()
	return newPKI(t, time.Hour, edit)
}

// NewPKIForDuration mints a synthetic chain whose certificates all remain
// valid for the requested workload. It is intended for long-running lab tests.
func NewPKIForDuration(t testing.TB, duration time.Duration) PKI {
	t.Helper()
	if duration <= 0 {
		t.Fatal("synthetic PKI validity must be positive")
	}
	return newPKI(t, duration, nil)
}

func newPKI(t testing.TB, duration time.Duration, edit func(*x509.Certificate)) PKI {
	t.Helper()
	now := time.Now()
	rootKey := key(t)
	root := certificate(1, "Test OpenVPN CA", now, duration)
	root.IsCA = true
	root.BasicConstraintsValid = true
	root.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	ca := sign(t, root, root, rootKey, rootKey)
	server := certificate(2, TestServerName, now, duration)
	server.KeyUsage = x509.KeyUsageDigitalSignature
	server.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	server.DNSNames = []string{TestServerName}
	server.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	if edit != nil {
		edit(server)
	}

	client := certificate(3, "OpenVPN test client", now, duration)
	client.KeyUsage = x509.KeyUsageDigitalSignature
	client.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	return PKI{
		CA:     ca.Certificate,
		Server: sign(t, server, root, key(t), rootKey),
		Client: sign(t, client, root, key(t), rootKey),
		issuer: rootKey,
	}
}

func (p PKI) ServerFingerprint() string {
	block, _ := pem.Decode(p.Server.Certificate)
	return strings.ReplaceAll(fmt.Sprintf("% X", sha256.Sum256(block.Bytes)), " ", ":")
}

func (p PKI) CRL(t testing.TB, now time.Time, revoked bool) []byte {
	t.Helper()
	block, _ := pem.Decode(p.CA)
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	list := &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute),
	}
	if revoked {
		list.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: now.Add(-time.Minute)}}
	}
	raw, err := x509.CreateRevocationList(rand.Reader, list, root, p.issuer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: raw})
}

func certificate(serial int64, name string, now time.Time, duration time.Duration) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(duration),
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
