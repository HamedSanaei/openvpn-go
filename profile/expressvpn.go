package profile

import "github.com/hamedsanaei/openvpn-go/client"

var expressDirectives = map[string]directive{
	"comp-lzo":     {min: 1, max: 1},
	"fast-io":      {},
	"fragment":     {min: 1, max: 1},
	"mssfix":       {min: 1, max: 1},
	"ns-cert-type": {min: 1, max: 1},
	"rcvbuf":       {min: 1, max: 1},
	"route-delay":  {min: 1, max: 1},
	"route-method": {min: 1, max: 1},
	"sndbuf":       {min: 1, max: 1},
}

type expressOptions struct {
	fragment int
	lzoStub  bool
}

func (p *parser) applyExpress(loc location, args []string) error {
	switch loc.name {
	case "comp-lzo":
		if args[0] != "no" {
			return loc.diagnostic(CodeUnsupported)
		}
		if p.express.lzoStub {
			return loc.diagnostic(CodeConflict)
		}
		p.express.lzoStub = true
		return nil
	case "fragment":
		n, ok := uintValue(args[0], 16)
		if !ok || n < 256 || n > 65507 {
			return loc.diagnostic(CodeValue)
		}
		if p.express.fragment != 0 {
			return loc.diagnostic(CodeConflict)
		}
		p.express.fragment = int(n)
		return nil
	case "ns-cert-type":
		if args[0] != "server" {
			return loc.diagnostic(CodeUnsupported)
		}
		p.cfg.TLS.RequireServerUsage = true
		return nil
	case "route-method":
		if args[0] != "exe" {
			return loc.diagnostic(CodeUnsupported)
		}
	case "mssfix", "rcvbuf", "sndbuf", "route-delay":
		if _, ok := uintValue(args[0], 31); !ok {
			return loc.diagnostic(CodeValue)
		}
	}
	p.warn(loc)
	return nil
}

func (p *parser) finishExpress() error {
	if !p.opts.ExpressVPNManual {
		return nil
	}
	if p.opts.protonImportEnabled() || p.opts.AllowPasswordOnly {
		return (location{}).diagnostic(CodeConflict)
	}
	for _, requirement := range []struct {
		name string
		ok   bool
	}{
		{"remote-cert-tls", p.cfg.TLS.RequireServerUsage},
		{"verify-x509-name", p.identity.Mode == client.X509NamePrefix},
		{"fragment", p.express.fragment != 0},
		{"comp-lzo", p.express.lzoStub},
		{"auth-user-pass", p.auth != nil},
		{"cert", p.cert != nil},
		{"key", p.key != nil},
	} {
		if !requirement.ok {
			return (location{name: requirement.name}).diagnostic(CodeRequired)
		}
	}
	if p.auth.inline || p.auth.path != "" {
		return p.auth.loc.diagnostic(CodeUnsupported)
	}
	p.identity.Mode = client.X509CommonNamePrefix
	return nil
}
