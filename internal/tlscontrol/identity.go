package tlscontrol

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func ValidVersions(minimum, maximum uint16) bool {
	return (minimum == 0 || minimum == tls.VersionTLS12 || minimum == tls.VersionTLS13) &&
		(maximum == 0 || maximum == tls.VersionTLS12 || maximum == tls.VersionTLS13) &&
		(maximum == 0 || minimum <= maximum)
}

func ValidNamePolicy(mode, value string) bool {
	switch mode {
	case "":
		return value == ""
	case "name", "name-prefix":
		return len(value) <= 1024 && validNameText(value)
	case "subject":
		_, ok := parseSubject(value)
		return ok
	default:
		return false
	}
}

// PeerConfig binds verification to an endpoint. Exact X.509 identities
// replace Go's SAN check and explicitly perform the complete chain check.
func PeerConfig(base *tls.Config, serverName, mode, value string, requireUsage bool) *tls.Config {
	return PeerConfigWithTrust(base, serverName, mode, value, requireUsage, ServerTrust{})
}

func PeerConfigWithTrust(base *tls.Config, serverName, mode, value string, requireUsage bool, trust ServerTrust) *tls.Config {
	cfg := base.Clone()
	cfg.ServerName = serverName
	if mode == "" && !requireUsage && len(trust.pins) == 0 && len(trust.crls) == 0 {
		return cfg
	}
	exact := mode == "name" || mode == "subject"
	cfg.InsecureSkipVerify = exact // VerifyConnection performs full chain verification for exact policies.
	subject, _ := parseSubject(value)
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return ErrCertificate
		}
		leaf := state.PeerCertificates[0]
		chains, now := state.VerifiedChains, time.Now()
		if base.Time != nil {
			now = base.Time()
		}
		if exact {
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			opts := x509.VerifyOptions{Roots: base.RootCAs, Intermediates: intermediates,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now}
			var err error
			chains, err = leaf.Verify(opts)
			if err != nil {
				return ErrCertificate
			}
		}
		if requireUsage && !serverUsage(leaf) {
			return ErrCertificate
		}
		if !matchName(leaf, mode, value, subject) || !trust.verify(leaf, chains, now) {
			return ErrCertificate
		}
		return nil
	}
	return cfg
}

func serverUsage(leaf *x509.Certificate) bool {
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return false
	}
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) {
			return true
		}
	}
	return false
}

func matchName(leaf *x509.Certificate, mode, expected string, subject []subjectAttribute) bool {
	if mode == "" {
		return true
	}
	var name pkix.RDNSequence
	if rest, err := asn1.Unmarshal(leaf.RawSubject, &name); err != nil || len(rest) != 0 {
		return false
	}
	if mode == "subject" {
		if len(subject) == 0 || len(subject) != len(name) {
			return false
		}
		for i, set := range name {
			if len(set) != 1 || set[0].Type.String() != subject[i].oid {
				return false
			}
			value, ok := set[0].Value.(string)
			if !ok || value != subject[i].value {
				return false
			}
		}
		return true
	}

	var commonName string
	found := false
	for _, set := range name {
		for _, attribute := range set {
			if !attribute.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
				continue
			}
			value, ok := attribute.Value.(string)
			if found || !ok || !validNameText(value) {
				return false
			}
			commonName, found = value, true
		}
	}
	if !found {
		return false
	}
	if mode == "name-prefix" {
		return strings.HasPrefix(commonName, expected)
	}
	return commonName == expected
}

func validNameText(s string) bool {
	return s != "" && strings.TrimSpace(s) == s && utf8.ValidString(s) &&
		!strings.ContainsFunc(s, unicode.IsControl)
}

type subjectAttribute struct {
	oid, value string
}

var subjectOIDs = map[string]string{
	"C": "2.5.4.6", "ST": "2.5.4.8", "L": "2.5.4.7", "O": "2.5.4.10",
	"OU": "2.5.4.11", "CN": "2.5.4.3", "street": "2.5.4.9",
	"serialNumber": "2.5.4.5", "SN": "2.5.4.4", "GN": "2.5.4.42",
	"emailAddress": "1.2.840.113549.1.9.1", "DC": "0.9.2342.19200300.100.1.25",
	"UID": "0.9.2342.19200300.100.1.1",
}

// parseSubject reads a complete DN in certificate order, with one attribute
// per RDN. Escapes distinguish literal delimiters from DN syntax.
func parseSubject(s string) ([]subjectAttribute, bool) {
	if len(s) > 4096 || !validNameText(s) {
		return nil, false
	}
	var attributes []subjectAttribute
	for {
		key, rest, ok := strings.Cut(strings.TrimLeft(s, " "), "=")
		if !ok || key == "" {
			return nil, false
		}
		oid := subjectOIDs[key]
		if oid == "" {
			parsed, err := x509.ParseOID(key)
			if err != nil {
				return nil, false
			}
			oid = parsed.String()
		}
		value, next, more, ok := subjectValue(rest)
		if !ok {
			return nil, false
		}
		attributes = append(attributes, subjectAttribute{oid: oid, value: value})
		if !more {
			return attributes, true
		}
		s = next
	}
}

func subjectValue(s string) (string, string, bool, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ',':
			return b.String(), s[i+1:], true, validNameText(b.String())
		case '+', '=':
			return "", "", false, false
		case '\\':
			i++
			if i == len(s) || !strings.ContainsRune(",+=\\", rune(s[i])) {
				return "", "", false, false
			}
		}
		b.WriteByte(s[i])
	}
	return b.String(), "", false, validNameText(b.String())
}
