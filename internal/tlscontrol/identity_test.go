package tlscontrol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestPeerIdentityPolicies(t *testing.T) {
	pki := testkit.NewPKIWithServer(t, func(server *x509.Certificate) {
		server.Subject.Country = []string{"US"}
		server.Subject.Organization = []string{"Example, Test"}
	})
	wrongCA := testkit.NewPKI(t).CA
	noKU := testkit.NewPKIWithServer(t, func(server *x509.Certificate) { server.KeyUsage = 0 })
	noEKU := testkit.NewPKIWithServer(t, func(server *x509.Certificate) { server.ExtKeyUsage = nil })
	wrongEKU := testkit.NewPKIWithServer(t, func(server *x509.Certificate) {
		server.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	})
	duplicateCN := testkit.NewPKIWithServer(t, func(server *x509.Certificate) {
		oid := asn1.ObjectIdentifier{2, 5, 4, 3}
		var err error
		server.RawSubject, err = asn1.Marshal(pkix.RDNSequence{
			{{Type: oid, Value: "a"}}, {{Type: oid, Value: "b"}},
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	host := testkit.TestServerName
	const missingSAN = "no-san-match.example.test"
	const dn = "C=US, O=Example\\, Test, CN=vpn.example.test"
	for _, tc := range []struct {
		name, host, mode, value string
		server                  testkit.PKI
		roots                   []byte
		clockShift              time.Duration
		wantFailure             bool
	}{
		{"dns_san", host, "", "", pki, pki.CA, 0, false},
		{"ip_san", "127.0.0.1", "", "", pki, pki.CA, 0, false},
		{"exact_common_name", missingSAN, "name", host, pki, pki.CA, 0, false},
		{"wrong_common_name", host, "name", "other.example.test", pki, pki.CA, 0, true},
		{"exact_subject", missingSAN, "subject", dn, pki, pki.CA, 0, false},
		{"subject_requires_full_dn", host, "subject", "CN=vpn.example.test", pki, pki.CA, 0, true},
		{"wrong_subject", host, "subject", "C=US, O=Other, CN=vpn.example.test", pki, pki.CA, 0, true},
		{"prefix_and_SAN", host, "name-prefix", "vpn.", pki, pki.CA, 0, false},
		{"prefix_with_wrong_SAN", missingSAN, "name-prefix", "vpn.", pki, pki.CA, 0, true},
		{"SAN_with_wrong_prefix", host, "name-prefix", "unused.", pki, pki.CA, 0, true},
		{"untrusted_exact_identity", missingSAN, "name", host, pki, wrongCA, 0, true},
		{"expired_exact_identity", missingSAN, "name", host, pki, pki.CA, 2 * time.Hour, true},
		{"not_yet_valid_exact_identity", missingSAN, "name", host, pki, pki.CA, -2 * time.Hour, true},
		{"wrong_EKU_chain", missingSAN, "name", host, wrongEKU, wrongEKU.CA, 0, true},
		{"missing_explicit_KU", host, "", "", noKU, noKU.CA, 0, true},
		{"missing_explicit_EKU", host, "", "", noEKU, noEKU.CA, 0, true},
		{"ambiguous_common_name", host, "name", "b", duplicateCN, duplicateCN.CA, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, err := ClientConfig(tc.roots, tc.server.Client.Certificate, tc.server.Client.PrivateKey, false, false)
			if err != nil {
				t.Fatal(err)
			}
			config.Time = func() time.Time { return time.Now().Add(tc.clockShift) }
			peer := PeerConfig(config, tc.host, tc.mode, tc.value, true)
			if config.ServerName != "" || config.VerifyConnection != nil {
				t.Fatal("peer settings mutated the shared TLS configuration")
			}
			identity, err := tls.X509KeyPair(tc.server.Server.Certificate, tc.server.Server.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			err = testPeerHandshake(t, peer, identity)
			if tc.wantFailure {
				var verify *tls.CertificateVerificationError
				if !errors.Is(err, ErrCertificate) && !errors.As(err, &verify) {
					t.Fatalf("TLS handshake = %v, want a certificate error", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testPeerHandshake(t *testing.T, peer *tls.Config, identity tls.Certificate) error {
	t.Helper()
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
	remote, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()

	var echoedSNI string
	server := tls.Server(remote, &tls.Config{
		Certificates: []tls.Certificate{identity},
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			echoedSNI = info.ServerName
			return nil, nil
		},
	})
	done := make(chan error, 1)
	go func() { done <- server.HandshakeContext(ctx) }()
	err = tls.Client(local, peer).HandshakeContext(ctx)
	serverErr := <-done
	if err == nil && serverErr != nil {
		t.Fatalf("server handshake failed: %v", serverErr)
	}
	wantSNI := peer.ServerName
	if net.ParseIP(wantSNI) != nil {
		wantSNI = ""
	}
	if echoedSNI != wantSNI {
		t.Fatalf("SNI = %q, want %q", echoedSNI, wantSNI)
	}
	return err
}

func TestSubjectPolicyRejectsAmbiguousOrMalformedNames(t *testing.T) {
	for _, value := range []string{"", " CN=test", "CN=test,", "CN=test+OU=x", "CN=test\\", "CN=test\n", "CN="} {
		if ValidNamePolicy("subject", value) {
			t.Fatalf("accepted malformed subject %q", value)
		}
	}
	pki := testkit.NewPKIWithServer(t, func(server *x509.Certificate) {
		server.Subject = pkix.Name{CommonName: "vpn=server"}
	})
	cert, err := tls.X509KeyPair(pki.Server.Certificate, pki.Server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	subject, ok := parseSubject("2.5.4.3=vpn\\=server")
	if !ok || !matchName(cert.Leaf, "subject", "", subject) {
		t.Fatal("escaped DN value did not match the complete subject")
	}
}
