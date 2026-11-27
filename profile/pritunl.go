package profile

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
)

// Pritunl's inline exporter includes metadata and platform-specific hints.
// No arbitrary ignore-unknown-option, script, or environment setting is enabled.
var pritunlDirectives = map[string]directive{
	"ignore-unknown-option": {min: 1, max: 1},
	"setenv":                {min: 2, max: 2},
	"push-peer-info":        {},
	"mute":                  {min: 1, max: 1},
	"ping":                  {min: 1, max: 1},
	"ping-restart":          {min: 1, max: 1},
	"sndbuf":                {min: 1, max: 1},
	"rcvbuf":                {min: 1, max: 1},
	"block-outside-dns":     {},
	"cipher":                {min: 1, max: 1},
	"data-ciphers":          {min: 1, max: 1},
	"reneg-sec":             {min: 1, max: 1},
}

func (p *parser) applyPritunl(loc location, args []string) error {
	key := loc.name
	switch loc.name {
	case "ignore-unknown-option":
		if args[0] != "data-ciphers" && args[0] != "block-outside-dns" {
			return loc.diagnostic(CodeUnsupported)
		}
		key += ":" + args[0]
	case "setenv":
		switch args[0] {
		case "UV_ID":
			if len(args[1]) != 32 {
				return loc.diagnostic(CodeValue)
			}
			if _, err := hex.DecodeString(args[1]); err != nil {
				return loc.diagnostic(CodeValue)
			}
		case "UV_NAME":
			if len(args[1]) == 0 || len(args[1]) > 128 {
				return loc.diagnostic(CodeValue)
			}
		default:
			return loc.diagnostic(CodeUnsupported)
		}
		key += ":" + args[0]
	case "mute":
		if n, ok := uintValue(args[0], 16); !ok || n > 1000 {
			return loc.diagnostic(CodeValue)
		}
	case "ping", "ping-restart":
		if _, ok := seconds(args[0], 0, 65535); !ok {
			return loc.diagnostic(CodeValue)
		}
	case "sndbuf", "rcvbuf":
		if _, ok := uintValue(args[0], 31); !ok {
			return loc.diagnostic(CodeValue)
		}
	case "cipher":
		switch args[0] {
		case "AES-128-CBC", "AES-256-CBC":
			p.pritunlLegacyCipher = args[0]
		case crypt.AES128GCM, crypt.AES256GCM, "CHACHA20-POLY1305":
		default:
			return loc.diagnostic(CodeUnsupported)
		}
	case "data-ciphers":
		// Only remove the exact optional CBC fallback produced by this exporter.
		value := args[0]
		switch value {
		case "AES-128-GCM:AES-128-CBC":
			value = "AES-128-GCM"
		case "AES-256-GCM:AES-256-CBC":
			value = "AES-256-GCM"
		}
		ciphers, err := crypt.DataCiphers(strings.Split(value, ":"))
		if err != nil {
			return loc.diagnostic(CodeUnsupported)
		}
		p.cfg.DataCiphers = ciphers
		if value == args[0] {
			if err := p.markPritunl(key, loc); err != nil {
				return err
			}
			return nil
		}
	case "reneg-sec":
		n, ok := seconds(args[0], 0, 2592000)
		if !ok {
			return loc.diagnostic(CodeValue)
		}
		// Retain the core's existing maximum instead of accepting 30-day key lifetimes.
		p.cfg.RekeyInterval, p.cfg.DisableTimedRekey = min(n, 7*24*time.Hour), n == 0
		if n <= 7*24*time.Hour {
			return p.markPritunl(key, loc)
		}
	}
	if err := p.markPritunl(key, loc); err != nil {
		return err
	}
	p.warn(loc)
	return nil
}

func (p *parser) markPritunl(key string, loc location) error {
	if p.pritunlSeen == nil {
		p.pritunlSeen = make(map[string]location)
	}
	if _, exists := p.pritunlSeen[key]; exists {
		return loc.diagnostic(CodeConflict)
	}
	p.pritunlSeen[key] = loc
	return nil
}

func (p *parser) finishPritunl() error {
	if p.opts.PritunlServerName == "" {
		return nil
	}
	loc := location{name: "verify-x509-name"}
	if p.opts.AccessServerName != "" || p.opts.ExpressVPNManual || p.opts.protonImportEnabled() || p.opts.AllowPasswordOnly {
		return loc.diagnostic(CodeConflict)
	}
	expected := client.X509Name{Mode: client.X509CommonName, Value: p.opts.PritunlServerName}
	if expected.Validate() != nil {
		return loc.diagnostic(CodeValue)
	}
	if p.identity.Mode != "" && p.identity != expected {
		return loc.diagnostic(CodeConflict)
	}
	if !p.cfg.TLS.RequireServerUsage {
		return (location{name: "remote-cert-tls"}).diagnostic(CodeRequired)
	}
	if len(p.cfg.DataCiphers) == 0 {
		return (location{name: "data-ciphers"}).diagnostic(CodeRequired)
	}
	if p.pritunlLegacyCipher != "" && (len(p.cfg.DataCiphers) != 1 || strings.TrimSuffix(p.pritunlLegacyCipher, "CBC")+"GCM" != p.cfg.DataCiphers[0]) {
		return (location{name: "cipher"}).diagnostic(CodeConflict)
	}
	if p.cert == nil {
		return (location{name: "cert"}).diagnostic(CodeRequired)
	}
	p.identity = expected
	return nil
}
