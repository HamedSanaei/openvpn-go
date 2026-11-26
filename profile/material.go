package profile

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
)

// Resolver opens a file authorized by the caller. The path is relative and
// slash-separated. The caller's implementation must confine resolution,
// reject special files and return a promptly readable regular file. Parse
// owns and closes the returned file and applies its aggregate byte limit.
type Resolver func(path string) (fs.File, error)

// KeyIdentity supplies an external key for the profile's cert directive.
// Exactly one of Signer and Provider may be set.
type KeyIdentity struct {
	Signer   crypto.Signer
	Provider func(context.Context) (crypto.Signer, error)
}

type material struct {
	loc       location
	path      string
	inline    bool
	body      []byte
	direction client.KeyDirection
}

func (p *parser) setMaterial(m *material) error {
	var target **material
	switch m.loc.name {
	case "ca":
		target = &p.ca
	case "cert":
		target = &p.cert
	case "key":
		target = &p.key
	case "auth-user-pass":
		target = &p.auth
	case "crl-verify":
		target = &p.crl
	case "peer-fingerprint":
		if len(p.pins) == 32 {
			return m.loc.diagnostic(CodeLimit)
		}
		p.pins = append(p.pins, m)
		return nil
	default:
		return p.setProtection(m)
	}
	if *target != nil {
		return m.loc.diagnostic(CodeConflict)
	}
	*target = m
	return nil
}

func (p *parser) loadTLS() error {
	identity := p.opts.Identity
	external := identity.Signer != nil || identity.Provider != nil
	if external && (p.key != nil || identity.Signer != nil && identity.Provider != nil) {
		return (location{name: "key"}).diagnostic(CodeConflict)
	}
	passwordOnly := !external && p.opts.AllowPasswordOnly &&
		(p.auth != nil || p.opts.Authentication.Credentials != nil) && p.cert == nil && p.key == nil
	for _, required := range []struct {
		name string
		ref  *material
		dest *[]byte
	}{
		{"ca", p.ca, &p.cfg.TLS.CA},
		{"cert", p.cert, &p.cfg.TLS.Certificate},
		{"key", p.key, &p.cfg.TLS.PrivateKey},
	} {
		if required.ref == nil {
			if passwordOnly && required.name != "ca" || external && required.name == "key" {
				continue
			}
			return (location{name: required.name}).diagnostic(CodeRequired)
		}
		raw, err := p.load(required.ref)
		if err != nil {
			return err
		}
		valid := validCertificatePEM
		if required.name == "key" {
			valid = validPrivateKeyPEM
		}
		if !valid(raw) {
			return required.ref.loc.diagnostic(CodeMaterial)
		}
		*required.dest = raw
	}
	if len(p.cfg.TLS.CA)+len(p.cfg.TLS.Certificate)+len(p.cfg.TLS.PrivateKey) > maxProfile {
		return p.ca.loc.diagnostic(CodeLimit)
	}
	if external {
		if err := tlscontrol.SetKeyProvider(&tls.Config{}, p.cfg.TLS.Certificate, identity.Signer, identity.Provider); err != nil {
			return p.cert.loc.diagnostic(CodeMaterial)
		}
		p.cfg.TLS.Signer, p.cfg.TLS.KeyProvider = identity.Signer, identity.Provider
	} else if !passwordOnly {
		if _, err := tls.X509KeyPair(p.cfg.TLS.Certificate, p.cfg.TLS.PrivateKey); err != nil {
			return p.key.loc.diagnostic(CodeMaterial)
		}
	}
	p.cfg.TLS.AllowPasswordOnly = passwordOnly
	if err := p.loadTrust(); err != nil {
		return err
	}
	return p.loadCredentials()
}

func (p *parser) loadTrust() error {
	settings := p.cfg.TLS
	for _, ref := range p.pins {
		raw, err := p.load(ref)
		if err != nil {
			return err
		}
		start := len(settings.ServerFingerprints)
		for line := range bytes.SplitSeq(raw, []byte{'\n'}) {
			line = bytes.TrimSpace(line)
			if len(line) != 0 {
				settings.ServerFingerprints = append(settings.ServerFingerprints, string(line))
			}
			if len(settings.ServerFingerprints) > 32 {
				return ref.loc.diagnostic(CodeLimit)
			}
		}
		if len(settings.ServerFingerprints) == start {
			return ref.loc.diagnostic(CodeMaterial)
		}
		if _, err := tlscontrol.ParseServerTrust(settings.ServerFingerprints, nil); err != nil {
			return ref.loc.diagnostic(CodeMaterial)
		}
	}
	if p.crl != nil {
		raw, err := p.load(p.crl)
		if err != nil {
			return err
		}
		if len(raw) == 0 {
			return p.crl.loc.diagnostic(CodeMaterial)
		}
		if _, err := tlscontrol.ParseServerTrust(nil, raw); err != nil {
			return p.crl.loc.diagnostic(CodeMaterial)
		}
		settings.CRL = raw
	}
	if len(settings.CA)+len(settings.Certificate)+len(settings.PrivateKey)+len(settings.CRL) > maxProfile {
		return p.crl.loc.diagnostic(CodeLimit)
	}
	return nil
}

func (p *parser) loadCredentials() error {
	m := p.auth
	if m == nil {
		return nil
	}
	var credentials client.Credentials
	if p.opts.Authentication.Credentials != nil {
		if m.inline || m.path != "" || p.opts.Credentials != nil {
			return m.loc.diagnostic(CodeConflict)
		}
		return nil
	}
	if !m.inline && m.path == "" {
		if p.opts.Credentials == nil {
			return m.loc.diagnostic(CodeRequired)
		}
		credentials = *p.opts.Credentials
	} else {
		raw, err := p.load(m)
		if err != nil {
			return err
		}
		defer clear(raw)
		user, rest, ok := bytes.Cut(raw, []byte{'\n'})
		pass, trailing, _ := bytes.Cut(rest, []byte{'\n'})
		if !ok || len(trailing) != 0 {
			return m.loc.diagnostic(CodeMaterial)
		}
		credentials.Username = string(bytes.TrimSuffix(user, []byte{'\r'}))
		credentials.Password = string(bytes.TrimSuffix(pass, []byte{'\r'}))
	}
	if user := tlscontrol.Credentials(credentials); user.Validate() != nil {
		return m.loc.diagnostic(CodeMaterial)
	}
	if strings.ContainsAny(credentials.Username, "\r\n") || strings.ContainsAny(credentials.Password, "\r\n") {
		return m.loc.diagnostic(CodeMaterial)
	}
	p.cfg.Credentials = &credentials
	return nil
}

func validCertificatePEM(raw []byte) bool {
	rest := bytes.TrimRightFunc(raw, unicode.IsSpace)
	if len(rest) == 0 {
		return false
	}
	for len(rest) != 0 {
		block, next := nextPEM(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		rest = next
	}
	return true
}

func validPrivateKeyPEM(raw []byte) bool {
	block, rest := nextPEM(raw)
	if block == nil {
		return false
	}
	defer clear(block.Bytes)
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		return len(bytes.TrimSpace(rest)) == 0
	default:
		return false
	}
}

// nextPEM rejects skipped content, including an invalid block preceding a
// valid one. pem.Decode alone scans forward until it finds a valid block.
func nextPEM(raw []byte) (*pem.Block, []byte) {
	const begin = "-----BEGIN "
	content := bytes.TrimLeftFunc(raw, unicode.IsSpace)
	offset := len(raw) - len(content)
	if offset != 0 && raw[offset-1] != '\n' {
		return nil, nil
	}
	raw = content
	if !bytes.HasPrefix(raw, []byte(begin)) {
		return nil, nil
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, nil
	}
	if len(block.Headers) != 0 || bytes.Contains(raw[:len(raw)-len(rest)], []byte("\n"+begin)) {
		clear(block.Bytes)
		return nil, nil
	}
	return block, rest
}

func (p *parser) load(m *material) ([]byte, error) {
	if raw, ok := p.loaded[m]; ok {
		return raw, nil
	}
	if m.inline {
		raw := bytes.Clone(m.body)
		p.loaded[m] = raw
		return raw, nil
	}
	f, before, code := p.open(m.path)
	if code != "" {
		return nil, m.loc.diagnostic(code)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() ||
		(before != nil && !os.SameFile(before, info)) {
		return nil, m.loc.diagnostic(CodeFile)
	}
	if info.Size() > int64(p.filesLeft) {
		return nil, m.loc.diagnostic(CodeLimit)
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(p.filesLeft)+1))
	if err != nil {
		clear(raw)
		return nil, m.loc.diagnostic(CodeFile)
	}
	if len(raw) > p.filesLeft {
		clear(raw)
		return nil, m.loc.diagnostic(CodeLimit)
	}
	p.filesLeft -= len(raw)
	p.loaded[m] = raw
	return raw, nil
}

func (p *parser) open(path string) (fs.File, fs.FileInfo, Code) {
	if p.opts.Resolver != nil {
		f, err := p.opts.Resolver(path)
		if err != nil || f == nil {
			if f != nil {
				f.Close()
			}
			return nil, nil, CodeFile
		}
		return f, nil, ""
	}
	if p.opts.Root == nil {
		return nil, nil, CodeFile
	}
	name, err := filepath.Localize(path)
	if err != nil {
		return nil, nil, CodeFile
	}
	// Reject existing special files before opening. Check the opened handle
	// before reading in case a path was replaced after the first stat.
	before, err := p.opts.Root.Stat(name)
	if err != nil || !before.Mode().IsRegular() {
		return nil, nil, CodeFile
	}
	if before.Size() > int64(p.filesLeft) {
		return nil, nil, CodeLimit
	}
	f, err := p.opts.Root.OpenFile(name, os.O_RDONLY|nonblockingOpen, 0)
	if err != nil {
		return nil, nil, CodeFile
	}
	return f, before, ""
}

func referencePath(s string) (string, bool) {
	if len(s) > 1024 {
		return "", false
	}
	s = strings.ReplaceAll(s, "\\", "/")
	if strings.ContainsAny(s, ":<>\"|?*") || strings.ContainsFunc(s, unicode.IsControl) {
		return "", false
	}
	var parts []string
	for component := range strings.SplitSeq(s, "/") {
		if component == "." {
			continue
		}
		if component == "" || strings.TrimRight(component, " .") != component || deviceName(component) {
			return "", false
		}
		parts = append(parts, component)
	}
	if len(parts) == 0 || strings.HasSuffix(s, "/.") {
		return "", false
	}
	s = strings.Join(parts, "/")
	return s, fs.ValidPath(s)
}

func deviceName(component string) bool {
	base, _, _ := strings.Cut(component, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		switch base[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return true
		}
	}
	return false
}
