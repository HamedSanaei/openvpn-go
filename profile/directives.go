package profile

import (
	"crypto/tls"
	"strconv"
	"strings"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
)

const maxFields = 4

type directive struct {
	min, max   int
	connection bool
	inline     bool
}

// The registry is also the allow-list for directive names in diagnostics.
var directives = map[string]directive{
	"client": {}, "tls-client": {}, "pull": {},
	"dev": {min: 1, max: 1}, "dev-type": {min: 1, max: 1},
	"connection": {}, "remote-random": {},
	"remote": {1, 3, true, false},
	"proto":  {1, 1, true, false}, "port": {1, 1, true, false}, "rport": {1, 1, true, false},
	"ca": {1, 1, false, true}, "cert": {1, 1, false, true}, "key": {1, 1, false, true},
	"peer-fingerprint": {1, 1, false, true}, "crl-verify": {1, 1, false, true},
	"auth-user-pass": {0, 1, false, true},
	"key-direction":  {1, 1, true, false},
	"tls-auth":       {1, 2, true, true},
	"tls-crypt":      {1, 1, true, true},
	"tls-crypt-v2":   {1, 1, true, true},
	"auth":           {min: 1, max: 1},
	"data-ciphers":   {min: 1, max: 1}, "cipher": {min: 1, max: 1},
	"remote-cert-tls": {min: 1, max: 1}, "verify-x509-name": {min: 1, max: 2},
	"tls-version-min": {min: 1, max: 2}, "tls-version-max": {min: 1, max: 1},
	"allow-compression": {min: 1, max: 1},
	"nobind":            {connection: true}, "disable-dco": {},
	"bind": {connection: true}, "local": {1, 1, true, false}, "lport": {1, 1, true, false},
	"connect-timeout": {1, 1, true, false}, "tun-mtu": {1, 1, true, false},
	"explicit-exit-notify": {0, 1, true, false},
	"compat-fixed-aead":    {1, 1, true, false},
	"connect-retry":        {min: 1, max: 2}, "connect-retry-max": {min: 1, max: 1},
	"hand-window": {min: 1, max: 1}, "reneg-sec": {min: 1, max: 1},
	"auth-nocache": {},
	"persist-key":  {}, "persist-tun": {}, "resolv-retry": {min: 1, max: 1}, "verb": {min: 1, max: 1},
}

// Recognized unsupported names get a specific diagnostic. Unknown names
// also fail closed and are omitted from diagnostics.
var unsupported = map[string]bool{
	"allow-pull-fqdn": true, "askpass": true, "auth-gen-token": true,
	"auth-retry": true, "auth-token": true, "auth-user-pass-verify": true,
	"capath": true, "cd": true, "compat-mode": true, "comp-lzo": true, "compress": true,
	"config": true, "data-ciphers-fallback": true, "dh": true,
	"down": true, "engine": true, "extra-certs": true, "float": true, "fragment": true,
	"http-proxy": true, "ignore-unknown-option": true, "key-method": true,
	"management": true, "mode": true, "ncp-ciphers": true, "ncp-disable": true,
	"no-replay": true, "ns-cert-type": true, "pkcs12": true,
	"plugin": true, "proto-force": true, "pull-filter": true, "remote-cert-eku": true,
	"remote-cert-ku": true, "remote-random-hostname": true, "route-up": true,
	"script-security": true, "secret": true, "server": true, "server-bridge": true,
	"setenv": true, "setenv-safe": true, "socks-proxy": true, "tls-cert-profile": true,
	"tls-cipher": true, "tls-ciphersuites": true, "tls-server": true, "tls-verify": true,
	"up": true, "verify-client-cert": true, "verify-hash": true, "x509-username-field": true,
}

func knownLocation(name string, line int) location {
	if _, ok := directives[name]; !ok && !unsupported[name] {
		name = ""
	}
	return location{line: line, name: name}
}

func (p *parser) apply(loc location, args []string) error {
	switch loc.name {
	case "client":
		p.tlsClient, p.pull = true, true
	case "tls-client":
		p.tlsClient = true
	case "pull":
		p.pull = true
	case "dev":
		if args[0] != "tun" && !isTunDevice(args[0]) {
			return loc.diagnostic(CodeUnsupported)
		}
		p.device = true
	case "dev-type":
		if args[0] != "tun" {
			return loc.diagnostic(CodeUnsupported)
		}
	case "remote-random":
		p.cfg.RemoteRandom = true
	case "remote", "proto", "port", "rport", "key-direction", "bind", "nobind", "local", "lport",
		"connect-timeout", "tun-mtu", "explicit-exit-notify", "compat-fixed-aead":
		return p.applyConnection(loc, args)
	case "auth-user-pass":
		if len(args) == 0 {
			return p.setMaterial(&material{loc: loc})
		}
		fallthrough
	case "ca", "cert", "key", "crl-verify", "peer-fingerprint", "tls-auth", "tls-crypt", "tls-crypt-v2":
		if loc.name == "peer-fingerprint" && strings.Contains(args[0], ":") {
			if _, err := tlscontrol.ParseServerTrust(args, nil); err != nil {
				return loc.diagnostic(CodeValue)
			}
			return p.setMaterial(&material{loc: loc, body: []byte(args[0]), inline: true})
		}
		path, ok := referencePath(args[0])
		if !ok {
			return loc.diagnostic(CodeFile)
		}
		m := &material{loc: loc, path: path}
		if len(args) == 2 {
			direction, ok := keyDirection(args[1])
			if !ok {
				return loc.diagnostic(CodeValue)
			}
			m.direction = direction
		}
		return p.setMaterial(m)
	case "auth":
		digest := strings.ToUpper(args[0])
		if digest == "" || !control.ValidAuthDigest(digest) {
			return loc.diagnostic(CodeUnsupported)
		}
		p.cfg.AuthDigest = digest
	case "data-ciphers", "cipher":
		names := strings.SplitN(args[0], ":", 4)
		if loc.name == "cipher" && len(names) != 1 {
			return loc.diagnostic(CodeValue)
		}
		ciphers, err := crypt.DataCiphers(names)
		if err != nil {
			return loc.diagnostic(CodeUnsupported)
		}
		if loc.name == "cipher" {
			p.warn(loc)
		} else {
			p.cfg.DataCiphers = ciphers
		}
	case "remote-cert-tls":
		if args[0] != "server" {
			return loc.diagnostic(CodeUnsupported)
		}
		p.cfg.TLS.RequireServerUsage = true
	case "verify-x509-name":
		if p.identity.Mode != "" {
			return loc.diagnostic(CodeConflict)
		}
		name := client.X509Name{Mode: client.X509Subject, Value: args[0]}
		if len(args) == 2 {
			name.Mode = client.X509NameMode(args[1])
		}
		if name.Mode == "" || name.Validate() != nil {
			return loc.diagnostic(CodeValue)
		}
		p.identity = name
	case "tls-version-min", "tls-version-max":
		return p.applyTLSVersion(loc, args)
	case "allow-compression":
		if args[0] != "no" {
			return loc.diagnostic(CodeUnsupported)
		}
	case "disable-dco":
		// These settings already describe the library's behavior.
	case "auth-nocache":
		p.noCache = loc
	case "resolv-retry":
		n, ok := uintValue(args[0], 8)
		switch {
		case args[0] == "infinite":
			p.cfg.ResolveRetry = client.ResolveUntilDialDeadline
		case ok && n <= 120:
			p.cfg.ResolveRetry = time.Duration(n) * time.Second
		default:
			return loc.diagnostic(CodeValue)
		}
	case "connect-retry":
		initial, ok := seconds(args[0], 1, 300)
		if !ok {
			return loc.diagnostic(CodeValue)
		}
		maximum := time.Duration(0)
		if len(args) == 2 {
			maximum, ok = seconds(args[1], int(initial/time.Second), 300)
			if !ok {
				return loc.diagnostic(CodeValue)
			}
		}
		p.cfg.Retry.InitialBackoff, p.cfg.Retry.MaxBackoff = initial, maximum
	case "connect-retry-max":
		n, ok := uintValue(args[0], 11)
		if !ok || n == 0 || n > 1024 {
			return loc.diagnostic(CodeValue)
		}
		p.attemptsPerRemote, p.attemptsLocation = int(n), loc
	case "hand-window":
		value, ok := seconds(args[0], 1, 300)
		if !ok {
			return loc.diagnostic(CodeValue)
		}
		p.cfg.HandshakeTimeout = value
	case "reneg-sec":
		value, ok := seconds(args[0], 0, 86400)
		if !ok {
			return loc.diagnostic(CodeValue)
		}
		p.cfg.RekeyInterval, p.cfg.DisableTimedRekey = value, value == 0
	case "verb":
		if level, ok := uintValue(args[0], 8); !ok || level > 11 {
			return loc.diagnostic(CodeValue)
		}
		p.warn(loc)
	case "persist-key", "persist-tun":
		p.warn(loc)
	}
	return nil
}

func seconds(value string, minimum, maximum int) (time.Duration, bool) {
	n, ok := uintValue(value, 32)
	return time.Duration(n) * time.Second, ok && n >= uint64(minimum) && n <= uint64(maximum)
}

func (p *parser) warn(loc location) {
	p.warnings = append(p.warnings, *loc.diagnostic(CodeIgnored))
}

func (p *parser) applyTLSVersion(loc location, args []string) error {
	version := tls.VersionTLS12
	switch args[0] {
	case "1.2":
	case "1.3":
		version = tls.VersionTLS13
	default:
		return loc.diagnostic(CodeUnsupported)
	}
	if len(args) == 2 && args[1] != "or-highest" {
		return loc.diagnostic(CodeValue)
	}
	if loc.name == "tls-version-min" {
		p.cfg.TLS.MinVersion = uint16(version)
	} else {
		p.cfg.TLS.MaxVersion = uint16(version)
	}
	p.versionLocation = loc
	return nil
}

func isTunDevice(s string) bool {
	number, ok := strings.CutPrefix(s, "tun")
	if !ok {
		return false
	}
	_, ok = uintValue(number, 32)
	return ok
}

func uintValue(s string, bits int) (uint64, bool) {
	if s == "" || strings.ContainsFunc(s, func(c rune) bool { return c < '0' || c > '9' }) {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, bits)
	return n, err == nil
}
