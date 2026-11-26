//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestTLSExporterMatchesOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL CLI is required for the independent TLS exporter check")
	}
	pki := testkit.NewPKI(t)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pki.CA, 0600); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pki.Server.Certificate, pki.Server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		flag    string
		version uint16
	}{{"-tls1_2", tls.VersionTLS12}, {"-tls1_3", tls.VersionTLS13}} {
		t.Run(test.flag[1:], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := listener.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			goResult := make(chan exporterResult, 1)
			go func() {
				material, err := exportFromTLSServer(ctx, listener, deadline, cert, test.version)
				goResult <- exporterResult{material, err}
			}()
			output, cliErr := exec.CommandContext(ctx, openssl, "s_client", test.flag,
				"-connect", listener.Addr().String(), "-servername", testkit.TestServerName,
				"-verify_hostname", testkit.TestServerName, "-verify_return_error", "-CAfile", ca,
				"-no_ign_eof", "-keymatexport", "EXPORTER-OpenVPN-datakeys",
				"-keymatexportlen", "256").Output()
			listener.Close()
			result := <-goResult
			defer clear(output)
			defer clear(result.material)
			if cliErr != nil || result.err != nil {
				t.Fatalf("exporter exchange failed: OpenSSL %v, Go %v", cliErr, result.err)
			}
			_, encoded, found := bytes.Cut(output, []byte("Keying material: "))
			encoded, _, _ = bytes.Cut(encoded, []byte("\n"))
			decoded := make([]byte, hex.DecodedLen(len(encoded)))
			defer clear(decoded)
			if n, err := hex.Decode(decoded, bytes.TrimSpace(encoded)); !found || err != nil || n != 256 ||
				!bytes.Equal(decoded[:n], result.material) {
				t.Fatal("Go and OpenSSL TLS exporter material differs")
			}
		})
	}
}

type exporterResult struct {
	material []byte
	err      error
}

func exportFromTLSServer(ctx context.Context, listener *net.TCPListener, deadline time.Time, cert tls.Certificate, version uint16) ([]byte, error) {
	raw, err := listener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, err
	}
	conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	material, err := state.ExportKeyingMaterial(crypt.ExporterLabel, nil, crypt.ExporterSize)
	if err != nil {
		return nil, err
	}
	// Let the peer finish before closing the transport.
	if _, err := io.Copy(io.Discard, conn); err != nil {
		clear(material)
		return nil, err
	}
	return material, nil
}
