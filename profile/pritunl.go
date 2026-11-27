package profile

import (
	"strings"
	"time"
	"unicode"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
)

// These narrowly-scoped directives occur in the official Pritunl export.
// They do not enable arbitrary environment variables or unknown options.
var pritunlDirectives = map[string]directive{
	"ignore-unknown-option": {min: 1, max: 1},
	"setenv":                {min: 2, max: 2},
	"mute":                  {min: 1, max: 1},
	"push-peer-info":        {},
	"ping":                  {min: 1, max: 1},
	"ping-restart":          {min: 1, max: 1},
	"sndbuf":                {min: 1, max: 1},
	"rcvbuf":                {min: 1, max: 1},
	"cipher":                {min: 1, max: 1},
	"data-ciphers":          {min: 1, max: 1},
	"reneg-sec":             {min: 1, max: 1},
}

func (p *parser) applyPritunl(loc location, args []string) error {
	key := loc.name
	if key == "setenv" {
		if args[0] != "UV_ID" && args[0] != "UV_NAME" {
			return loc.diagnostic(CodeUnsupported)
		}
		if len(args[1]) == 0 || len(args[1]) > 128 || strings.ContainsFunc(args[1], func(r rune) bool { return !unicode.IsPrint(r) }) {
			return loc.diagnostic(CodeValue)
		}
		key += ":" + args[0]
	}
	if p.pritunlSeen == nil {
		p.pritunlSeen = make(map[string]location)
	}
	if p.pritunlSeen[key].line != 0 {
		return loc.diagnostic(CodeConflict)
	}
	p.pritunlSeen[key] = loc
	switch loc.name {
	case "ignore-unknown-option":
		if args[0] != "data-ciphers" {
			return loc.diagnostic(CodeUnsupported)
		}
	case "setenv", "push-peer-info":
		// Advisory metadata only; do not transmit user/device identifiers.
	case "mute":
		if _, ok := uintValue(args[0], 16); !ok {
			return loc.diagnostic(CodeValue)
		}
	case "ping", "ping-restart":
		if _, ok := seconds(args[0], 1, 65535); !ok {
			return loc.diagnostic(CodeValue)
		}
		// The authenticated push governs tunnel liveness. Local hints are not applied.
	case "sndbuf", "rcvbuf":
		if _, ok := uintValue(args[0], 31); !ok {
			return loc.diagnostic(CodeValue)
		}
	case "cipher":
		if args[0] != "AES-128-CBC" && args[0] != "AES-256-CBC" {
			if _, err := crypt.DataCiphers(args); err != nil {
				return loc.diagnostic(CodeUnsupported)
			}
		}
		p.pritunlHint = args[0]
	case "data-ciphers":
		names := strings.Split(args[0], ":")
		if len(names) == 2 && (names[0] == "AES-128-GCM" && names[1] == "AES-128-CBC" || names[0] == "AES-256-GCM" && names[1] == "AES-256-CBC") {
			p.pritunlCBC = names[1]
			names = names[:1]
		}
		ciphers, err := crypt.DataCiphers(names)
		if err != nil {
			return loc.diagnostic(CodeUnsupported)
		}
		p.cfg.DataCiphers = ciphers
		if p.pritunlCBC == "" {
			return nil
		}
	case "reneg-sec":
		value, ok := seconds(args[0], 0, 2592000)
		if !ok {
			return loc.diagnostic(CodeValue)
		}
		if value > 7*24*time.Hour {
			// Never lengthen the existing client key lifetime ceiling.
			p.cfg.RekeyInterval = 7 * 24 * time.Hour
			p.cfg.DisableTimedRekey = false
		} else {
			p.cfg.RekeyInterval, p.cfg.DisableTimedRekey = value, value == 0
			return nil
		}
	}
	p.warn(loc)
	return nil
}

func (p *parser) finishPritunl() error {
	if p.opts.PritunlServerName == "" {
		return nil
	}
	loc := location{name: "verify-x509-name"}
	if p.opts.protonImportEnabled() || p.opts.ExpressVPNManual || p.opts.AccessServerName != "" || p.opts.AllowPasswordOnly {
		return loc.diagnostic(CodeConflict)
	}
	name := client.X509Name{Mode: client.X509CommonName, Value: p.opts.PritunlServerName}
	if name.Validate() != nil {
		return loc.diagnostic(CodeValue)
	}
	if p.identity.Mode != "" && p.identity != name {
		return loc.diagnostic(CodeConflict)
	}
	if !p.cfg.TLS.RequireServerUsage {
		return (location{name: "remote-cert-tls"}).diagnostic(CodeRequired)
	}
	if p.ca == nil || p.cert == nil {
		return (location{name: "cert"}).diagnostic(CodeRequired)
	}
	if p.pritunlSeen["data-ciphers"].line == 0 || len(p.cfg.DataCiphers) == 0 {
		return (location{name: "data-ciphers"}).diagnostic(CodeRequired)
	}
	if p.pritunlCBC != "" {
		if p.pritunlHint != p.pritunlCBC {
			return (location{name: "cipher"}).diagnostic(CodeConflict)
		}
	} else if p.pritunlHint != "" {
		if _, err := crypt.DataCiphers([]string{p.pritunlHint}); err != nil {
			return (location{name: "cipher"}).diagnostic(CodeConflict)
		}
		found := false
		for _, c := range p.cfg.DataCiphers {
			if c == p.pritunlHint {
				found = true
			}
		}
		if !found {
			return (location{name: "cipher"}).diagnostic(CodeConflict)
		}
	}
	p.identity = name
	return nil
}
