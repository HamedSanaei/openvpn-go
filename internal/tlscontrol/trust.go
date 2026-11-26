package tlscontrol

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"slices"
	"strings"
	"time"
)

// ServerTrust adds leaf pins and chain revocation checks after verification.
type ServerTrust struct {
	pins [][sha256.Size]byte
	crls []*x509.RevocationList
}

func ParseServerTrust(pins []string, crlPEM []byte) (ServerTrust, error) {
	var policy ServerTrust
	if len(pins) > 32 || len(crlPEM) > 1<<20 {
		return policy, ErrConfig
	}
	for _, pin := range pins {
		var digest [sha256.Size]byte
		if len(pin) != sha256.Size*3-1 {
			return ServerTrust{}, ErrConfig
		}
		for i, value := range strings.Split(pin, ":") {
			if i >= len(digest) || len(value) != 2 {
				return ServerTrust{}, ErrConfig
			}
			if _, err := hex.Decode(digest[i:i+1], []byte(value)); err != nil {
				return ServerTrust{}, ErrConfig
			}
		}
		if slices.Contains(policy.pins, digest) {
			return ServerTrust{}, ErrConfig
		}
		policy.pins = append(policy.pins, digest)
	}
	for raw := bytes.TrimSpace(crlPEM); len(raw) != 0; raw = bytes.TrimSpace(raw) {
		if !bytes.HasPrefix(raw, []byte("-----BEGIN X509 CRL-----")) || len(policy.crls) == 32 {
			return ServerTrust{}, ErrConfig
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "X509 CRL" || len(block.Headers) != 0 ||
			bytes.Count(raw[:len(raw)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return ServerTrust{}, ErrConfig
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil || !crl.NextUpdate.After(crl.ThisUpdate) {
			return ServerTrust{}, ErrConfig
		}
		for _, ext := range crl.Extensions {
			// Delta, scoped and indirect lists need different processing.
			if ext.Critical || ext.Id.String() == "2.5.29.27" || ext.Id.String() == "2.5.29.28" {
				return ServerTrust{}, ErrConfig
			}
		}
		for _, entry := range crl.RevokedCertificateEntries {
			for _, ext := range entry.Extensions {
				if ext.Critical || ext.Id.String() == "2.5.29.29" {
					return ServerTrust{}, ErrConfig
				}
			}
		}
		for _, other := range policy.crls {
			if bytes.Equal(other.RawIssuer, crl.RawIssuer) {
				return ServerTrust{}, ErrConfig
			}
		}
		policy.crls = append(policy.crls, crl)
		raw = rest
	}
	if len(crlPEM) != 0 && len(policy.crls) == 0 {
		return ServerTrust{}, ErrConfig
	}
	return policy, nil
}

func (p ServerTrust) verify(leaf *x509.Certificate, chains [][]*x509.Certificate, now time.Time) bool {
	if len(p.pins) != 0 && !slices.Contains(p.pins, sha256.Sum256(leaf.Raw)) {
		return false
	}
	if len(p.crls) == 0 {
		return true
	}
	for _, chain := range chains {
		if len(chain) >= 2 && p.currentChain(chain, now) {
			return true
		}
	}
	return false
}

func (p ServerTrust) currentChain(chain []*x509.Certificate, now time.Time) bool {
	for i, cert := range chain[:len(chain)-1] {
		found := slices.IndexFunc(p.crls, func(crl *x509.RevocationList) bool {
			return bytes.Equal(crl.RawIssuer, cert.RawIssuer)
		})
		if found < 0 {
			return false
		}
		crl := p.crls[found]
		if now.Before(crl.ThisUpdate) || !now.Before(crl.NextUpdate) ||
			crl.CheckSignatureFrom(chain[i+1]) != nil {
			return false
		}
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return false
			}
		}
	}
	return true
}
