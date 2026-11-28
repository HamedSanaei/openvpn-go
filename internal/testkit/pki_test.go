package testkit

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

func TestSoakPKIValidityIncludesReconnections(t *testing.T) {
	pki := NewPKIForDuration(t, 74*time.Hour)
	now := time.Now()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pki.CA) {
		t.Fatal("missing synthetic CA")
	}
	for _, endpoint := range []struct {
		identity Identity
		name     string
		usage    x509.ExtKeyUsage
	}{
		{pki.Server, TestServerName, x509.ExtKeyUsageServerAuth},
		{pki.Client, "", x509.ExtKeyUsageClientAuth},
	} {
		raw, _ := pem.Decode(endpoint.identity.Certificate)
		if raw == nil {
			t.Fatal("missing synthetic leaf")
		}
		leaf, err := x509.ParseCertificate(raw.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		options := x509.VerifyOptions{
			Roots: roots, DNSName: endpoint.name, KeyUsages: []x509.ExtKeyUsage{endpoint.usage},
			CurrentTime: now.Add(72 * time.Hour),
		}
		if _, err := leaf.Verify(options); err != nil {
			t.Fatalf("scheduled final rekey failed certificate verification: %v", err)
		}
		options.CurrentTime = now.Add(75 * time.Hour)
		_, err = leaf.Verify(options)
		var invalid x509.CertificateInvalidError
		if !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
			t.Fatalf("expected verification to reject expiration, got %v", err)
		}
	}
}
