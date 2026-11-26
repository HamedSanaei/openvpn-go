package profile

import (
	"net/netip"
	"strings"

	"github.com/hamedsanaei/openvpn-go/client"
)

var protonDirectives = map[string]directive{
	"block-outside-dns": {},
	"setenv":            {min: 2, max: 2},
	"mssfix":            {min: 1, max: 1},
	"script-security":   {min: 1, max: 1},
	"up":                {min: 1, max: 1},
	"down":              {min: 1, max: 1},
}

func (p *parser) applyProtonHint(loc location, args []string) error {
	var allowed bool
	switch loc.name {
	case "setenv":
		allowed = args[0] == "CLIENT_CERT" && args[1] == "0"
	case "mssfix":
		allowed = args[0] == "0"
	case "script-security":
		allowed = args[0] == "2"
	case "up", "down":
		allowed = args[0] == "/etc/openvpn/update-resolv-conf"
	case "block-outside-dns":
		allowed = true
	}
	if !allowed {
		return loc.diagnostic(CodeUnsupported)
	}
	if p.protonHints[loc.name].line != 0 {
		return loc.diagnostic(CodeConflict)
	}
	if p.protonHints == nil {
		p.protonHints = make(map[string]location)
	}
	p.protonHints[loc.name] = loc
	p.warn(loc)
	return nil
}

func (p *parser) checkProtonDNSHooks(report *Report) error {
	var first location
	count := 0
	for _, name := range []string{"script-security", "up", "down"} {
		loc := p.protonHints[name]
		if loc.line == 0 {
			continue
		}
		count++
		if first.line == 0 || loc.line < first.line {
			first = loc
		}
	}
	if count == 0 || count == 3 {
		return nil
	}
	if report != nil {
		for i, entry := range report.Entries {
			if entry.Line == first.line && entry.Directive == first.name {
				report.Entries[i].Capability = Rejected
				report.Entries[i].Code = CodeConflict
				return nil
			}
		}
	}
	return first.diagnostic(CodeConflict)
}

func (o Options) protonImportEnabled() bool {
	return o.ProtonVPNServerName != "" || o.ProtonVPNVerifyIP
}

func validProtonName(name string) bool {
	if _, err := (client.Endpoint{Host: name}).Validated(); err != nil || !strings.ContainsRune(name, '.') ||
		strings.HasSuffix(name, ".") {
		return false
	}
	_, ipErr := netip.ParseAddr(name)
	return ipErr != nil
}

func (p *parser) setProtonServerIdentity() error {
	if !p.opts.protonImportEnabled() {
		return nil
	}
	name := p.opts.ProtonVPNServerName
	loc := location{name: "verify-x509-name"}
	if p.opts.ProtonVPNVerifyIP {
		if name != "" || p.identity.Mode != "" {
			return loc.diagnostic(CodeConflict)
		}
	} else {
		if !validProtonName(name) {
			return loc.diagnostic(CodeValue)
		}
		expected := client.X509Name{Mode: client.X509CommonName, Value: name}
		if p.identity.Mode != "" && p.identity != expected {
			return loc.diagnostic(CodeConflict)
		}
		p.identity = expected
	}
	if !p.cfg.TLS.RequireServerUsage {
		return (location{name: "remote-cert-tls"}).diagnostic(CodeRequired)
	}
	if p.auth == nil {
		return (location{name: "auth-user-pass"}).diagnostic(CodeRequired)
	}
	if p.auth.path != "" || p.auth.inline {
		return p.auth.loc.diagnostic(CodeUnsupported)
	}
	if p.cert != nil || p.key != nil || p.opts.Identity.Signer != nil || p.opts.Identity.Provider != nil {
		return (location{name: "cert"}).diagnostic(CodeConflict)
	}
	return nil
}
