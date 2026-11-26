package tlscontrol

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"unicode/utf8"
)

const maxKeyString = 4096

var (
	ErrConfig          = errors.New("invalid OpenVPN TLS configuration")
	ErrCertificate     = errors.New("OpenVPN peer certificate verification failed")
	ErrAuth            = errors.New("OpenVPN authentication failed")
	ErrNegotiation     = errors.New("OpenVPN control negotiation failed")
	ErrPeerRestart     = errors.New("OpenVPN peer requested a restart")
	ErrPeerRestartSame = errors.New("OpenVPN peer requested a restart on the same endpoint")
	ErrPeerStopped     = errors.New("OpenVPN peer stopped the session")
)

type Credentials struct {
	Username string
	Password string
}

func (c Credentials) Validate() error {
	if c.Username == "" || c.Password == "" || !validKeyString(c.Username) || !validKeyString(c.Password) {
		return ErrConfig
	}
	return nil
}

func validKeyString(s string) bool {
	return len(s) < maxKeyString && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// ClientConfig loads a client key pair and explicitly provisioned trust.
func ClientConfig(ca, certificate, key []byte, systemRoots, allowPasswordOnly bool) (*tls.Config, error) {
	if (len(ca) == 0 && !systemRoots) || len(ca)+len(certificate)+len(key) > 1<<20 {
		return nil, ErrConfig
	}
	var roots *x509.CertPool
	if systemRoots {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, ErrConfig
		}
	} else {
		roots = x509.NewCertPool()
	}
	if len(ca) != 0 && !roots.AppendCertsFromPEM(ca) {
		return nil, ErrConfig
	}
	cfg := &tls.Config{
		RootCAs:                roots,
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}
	if len(certificate) == 0 && len(key) == 0 && allowPasswordOnly {
		return cfg, nil
	}
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return nil, ErrConfig
	}
	cfg.Certificates = []tls.Certificate{pair}
	return cfg, nil
}
