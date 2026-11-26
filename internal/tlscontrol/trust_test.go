package tlscontrol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestCRLChecksVerifiedChain(t *testing.T) {
	now := time.Now()
	issue := func(serial int64, name string, parent *x509.Certificate, signer *ecdsa.PrivateKey, ca bool) (*x509.Certificate, *ecdsa.PrivateKey) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			BasicConstraintsValid: true, IsCA: ca,
			KeyUsage: x509.KeyUsageDigitalSignature,
		}
		if ca {
			template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		if parent == nil {
			parent, signer = template, key
		}
		raw, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}
	list := func(issuer *x509.Certificate, signer *ecdsa.PrivateKey, revoked *x509.Certificate) []byte {
		t.Helper()
		template := &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Minute),
		}
		if revoked != nil {
			template.RevokedCertificateEntries = []x509.RevocationListEntry{
				{SerialNumber: revoked.SerialNumber, RevocationTime: now.Add(-time.Minute)},
			}
		}
		raw, err := x509.CreateRevocationList(rand.Reader, template, issuer, signer)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: raw})
	}
	root, rootKey := issue(1, "root", nil, nil, true)
	intermediate, intermediateKey := issue(2, "issuer", root, rootKey, true)
	leaf, _ := issue(3, "server", intermediate, intermediateKey, false)
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(intermediate)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now})
	if err != nil {
		t.Fatal(err)
	}
	issuerList := list(intermediate, intermediateKey, nil)
	rootList := list(root, rootKey, nil)
	for _, tc := range []struct {
		name   string
		bundle []byte
		valid  bool
	}{
		{"complete", bytes.Join([][]byte{issuerList, rootList}, nil), true},
		{"missing-root-list", issuerList, false},
		{"revoked-intermediate", bytes.Join([][]byte{issuerList, list(root, rootKey, intermediate)}, nil), false},
		{"revoked-leaf", bytes.Join([][]byte{list(intermediate, intermediateKey, leaf), rootList}, nil), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := ParseServerTrust(nil, tc.bundle)
			if err != nil {
				t.Fatal(err)
			}
			if policy.verify(leaf, chains, now) != tc.valid {
				t.Fatalf("server chain verification did not match policy")
			}
		})
	}
	if _, err := ParseServerTrust(nil, bytes.Join([][]byte{rootList, rootList}, nil)); err != ErrConfig {
		t.Fatal("duplicate issuer lists were accepted")
	}
}
