package client

import (
	"errors"
	"testing"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestPasswordOnlyClientValidation(t *testing.T) {
	pki := testkit.NewPKI(t)
	credentials := &Credentials{Username: "user", Password: "password"}
	for _, tc := range []struct {
		name  string
		tls   TLSConfig
		creds *Credentials
		valid bool
	}{
		{"explicit opt-in", TLSConfig{CA: pki.CA, AllowPasswordOnly: true}, credentials, true},
		{"implicit omission", TLSConfig{CA: pki.CA}, credentials, false},
		{"missing credentials", TLSConfig{CA: pki.CA, AllowPasswordOnly: true}, nil, false},
		{"missing trust", TLSConfig{AllowPasswordOnly: true}, credentials, false},
		{"missing private key", TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, AllowPasswordOnly: true}, credentials, false},
		{"missing certificate", TLSConfig{CA: pki.CA, PrivateKey: pki.Client.PrivateKey, AllowPasswordOnly: true}, credentials, false},
		{"certificate mode", TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(Config{Endpoints: []Endpoint{{Host: "vpn.example.test"}}, TLS: &tc.tls, Credentials: tc.creds})
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
			} else {
				var failure *Error
				if !errors.As(err, &failure) || failure.Code != CodeConfig {
					t.Fatalf("invalid identity policy = %v", err)
				}
			}
		})
	}
}
