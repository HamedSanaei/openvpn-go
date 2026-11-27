package client

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

func TestRuntimeCipherOffer(t *testing.T) {
	const subprocess = "OPENVPN_TEST_FIPS_MODE"
	if mode := os.Getenv(subprocess); mode != "" {
		testRuntimeCipherOffer(t, mode)
		return
	}
	for _, mode := range []string{"off", "on", "only"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRuntimeCipherOffer$")
			cmd.Env = append(os.Environ(), subprocess+"="+mode, "GODEBUG=fips140="+mode)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("FIPS mode %s: %v\n%s", mode, err, out)
			}
		})
	}
}

func testRuntimeCipherOffer(t *testing.T, mode string) {
	t.Helper()
	pki := testkit.NewPKI(t)
	for _, offer := range [][]string{
		nil, {crypt.AES128GCM}, {crypt.AES256GCM}, {crypt.ChaCha20Poly1305},
		{crypt.ChaCha20Poly1305, crypt.AES256GCM},
	} {
		cfg := Config{
			Endpoints:   []Endpoint{{Host: "vpn.example.test"}},
			TLS:         &TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey},
			DataCiphers: offer,
			Dialer: testkit.DialerFunc(func(context.Context, string, string) (transport.PacketConn, error) {
				t.Fatal("validation dialed the network")
				return nil, nil
			}),
			Authentication: Authentication{Credentials: func(context.Context) (Credentials, error) {
				t.Fatal("validation invoked the credential callback")
				return Credentials{}, nil
			}},
		}
		client, err := New(cfg)
		if mode == "only" {
			var failure *Error
			if !errors.As(err, &failure) || failure.Code != CodeConfig || failure.Field != "data ciphers" || client != nil {
				t.Fatalf("unavailable offer %v was not rejected: %v", offer, err)
			}
		} else {
			if err != nil {
				t.Fatalf("available offer %v was rejected: %v", offer, err)
			}
			client.Close()
		}
	}
}
