package tlscontrol

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"io"
	"reflect"

	"github.com/hamedsanaei/openvpn-go/internal/pemutil"
)

// KeyProvider supplies a signer for an authenticated TLS certificate request.
type KeyProvider func(context.Context) (crypto.Signer, error)

func SetKeyProvider(cfg *tls.Config, certificate []byte, signer crypto.Signer, provider KeyProvider) error {
	if signer != nil && provider != nil {
		return ErrConfig
	}
	chain, ok := pemutil.Certificates(certificate)
	if !ok || signer == nil && provider == nil || signer != nil && !keyMatches(signer, chain[0]) {
		return ErrConfig
	}
	identity := tls.Certificate{Leaf: chain[0], Certificate: make([][]byte, 0, len(chain))}
	for _, cert := range chain {
		identity.Certificate = append(identity.Certificate, cert.Raw)
	}
	cfg.GetClientCertificate = func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		ctx := request.Context()
		key := signer
		if provider != nil {
			var err error
			key, err = provider(ctx)
			if err := authCallbackError(ctx, err); err != nil {
				return nil, err
			}
			if !keyMatches(key, identity.Leaf) {
				return nil, ErrAuth
			}
		}
		pair := identity
		pair.PrivateKey = protectedSigner{Signer: key, ctx: ctx}
		if err := request.SupportsCertificate(&pair); err != nil {
			return nil, ErrAuth
		}
		return &pair, nil
	}
	return nil
}

func keyMatches(key crypto.Signer, leaf *x509.Certificate) bool {
	if key == nil {
		return false
	}
	value := reflect.ValueOf(key)
	switch value.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Func, reflect.Chan, reflect.Interface:
		if value.IsNil() {
			return false
		}
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return false
		}
	case *ed25519.PrivateKey:
		if len(*k) != ed25519.PrivateKeySize {
			return false
		}
	}
	expected, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && expected.Equal(key.Public())
}

type protectedSigner struct {
	crypto.Signer
	ctx context.Context
}

func (s protectedSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	var signature []byte
	var err error
	if key, ok := s.Signer.(interface {
		SignContext(context.Context, io.Reader, []byte, crypto.SignerOpts) ([]byte, error)
	}); ok {
		signature, err = key.SignContext(s.ctx, random, digest, opts)
	} else {
		signature, err = s.Signer.Sign(random, digest, opts)
	}
	if err := authCallbackError(s.ctx, err); err != nil {
		return nil, err
	}
	return signature, nil
}
