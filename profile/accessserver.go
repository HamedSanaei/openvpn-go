package profile

import "github.com/hamedsanaei/openvpn-go/client"

func (p *parser) finishAccessServer() error {
	if p.opts.AccessServerName == "" {
		return nil
	}
	loc := location{name: "verify-x509-name"}
	if p.opts.protonImportEnabled() || p.opts.ExpressVPNManual {
		return loc.diagnostic(CodeConflict)
	}
	expected := client.X509Name{Mode: client.X509CommonName, Value: p.opts.AccessServerName}
	if expected.Validate() != nil {
		return loc.diagnostic(CodeValue)
	}
	if p.identity.Mode != "" && p.identity != expected {
		return loc.diagnostic(CodeConflict)
	}
	if !p.cfg.TLS.RequireServerUsage {
		return (location{name: "remote-cert-tls"}).diagnostic(CodeRequired)
	}
	if p.accessNoCert && (p.cert != nil || p.key != nil || p.auth == nil ||
		p.opts.Identity.Signer != nil || p.opts.Identity.Provider != nil) {
		return (location{name: "setenv"}).diagnostic(CodeConflict)
	}
	p.identity = expected
	return nil
}
