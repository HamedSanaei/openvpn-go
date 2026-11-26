package tlscontrol

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"reflect"
)

// KeyProvider supplies a signer for an authenticated TLS certificate request.
type KeyProvider func(context.Context) (crypto.Signer, error)

func SetKeyProvider(cfg *tls.Config, certificate []byte, signer crypto.Signer, provider KeyProvider) error {
	if signer != nil && provider != nil {
		return ErrConfig
	}
	var identity tls.Certificate
	for raw := bytes.TrimSpace(certificate); len(raw) != 0; raw = bytes.TrimSpace(raw) {
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
			!bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) ||
			bytes.Count(raw[:len(raw)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return ErrConfig
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return ErrConfig
		}
		if identity.Leaf == nil {
			identity.Leaf = cert
		}
		identity.Certificate = append(identity.Certificate, block.Bytes)
		raw = rest
	}
	if identity.Leaf == nil || signer != nil && !keyMatches(signer, identity.Leaf) {
		return ErrConfig
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
	if key == nil || reflect.ValueOf(key).Kind() == reflect.Pointer && reflect.ValueOf(key).IsNil() {
		return false
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
