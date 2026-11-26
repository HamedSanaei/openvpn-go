package profile

import (
	"bytes"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
)

const (
	maxProfile   = 1 << 20
	maxFileBytes = 1 << 20
	maxLine      = 64 << 10
)

// Options authorizes profile material. With neither Root nor Resolver, only
// inline material is available. The caller retains ownership of Root.
type Options struct {
	Root     *os.Root
	Resolver Resolver
	// Credentials supplies the pair for auth-user-pass without an argument.
	Credentials *client.Credentials
	// AllowPasswordOnly authorizes a verified TLS profile with auth-user-pass
	// and no client certificate or key.
	AllowPasswordOnly bool
	// ProtonVPNServerName enables the Proton VPN manual import policy.
	// Supply the exact certificate common name from a trusted provider
	// source. The profile cannot set or override this value.
	ProtonVPNServerName string
	// Authentication authorizes caller-managed credentials and interaction.
	Authentication client.Authentication
	// Identity supplies a matching key for a profile with cert and no key.
	Identity KeyIdentity
}

// Parse reads a bounded profile and returns a validated configuration in
// declared remote order. A fatal error returns a zero Config and any warnings
// collected beforehand. The caller retains ownership of the reader.
func Parse(r io.Reader, opts Options) (client.Config, []Diagnostic, error) {
	if opts.Root != nil && opts.Resolver != nil {
		return client.Config{}, nil, (location{}).diagnostic(CodeConflict)
	}
	if r == nil {
		return client.Config{}, nil, (location{}).diagnostic(CodeRead)
	}
	data, err := io.ReadAll(io.LimitReader(r, maxProfile+1))
	defer clear(data)
	if err != nil {
		return client.Config{}, nil, (location{}).diagnostic(CodeRead)
	}
	if len(data) > maxProfile {
		return client.Config{}, nil, (location{}).diagnostic(CodeLimit)
	}
	p := parser{
		opts: opts, cfg: client.Config{TLS: &client.TLSConfig{}, Authentication: opts.Authentication},
		filesLeft: maxFileBytes, loaded: make(map[*material][]byte),
	}
	if err := p.read(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), nil); err != nil {
		return client.Config{}, p.warnings, err
	}
	if err := p.finish(); err != nil {
		for _, raw := range p.loaded {
			clear(raw)
		}
		return client.Config{}, p.warnings, err
	}
	return p.cfg, p.warnings, nil
}

type parser struct {
	opts              Options
	cfg               client.Config
	identity          client.X509Name
	versionLocation   location
	warnings          []Diagnostic
	tlsClient         bool
	pull              bool
	device            bool
	noCache           location
	attemptsPerRemote int
	attemptsLocation  location
	protonHints       map[string]location

	defaults connection
	remotes  []remote
	blocks   []connection
	block    *connection
	blockLoc location

	ca, cert, key, auth, crl *material
	pins                     []*material
	loaded                   map[*material][]byte
	filesLeft                int
}

func (p *parser) read(remaining []byte, report *Report) error {
	var inline *material
	var body []byte
	var skipTag string
	for number := 1; len(remaining) != 0; number++ {
		previous := remaining
		line, rest, _ := bytes.Cut(remaining, []byte{'\n'})
		remaining = rest
		line = bytes.TrimSuffix(line, []byte{'\r'})
		loc := location{line: number}
		if len(line) > maxLine {
			if err := report.record(loc, loc.diagnostic(CodeLimit), false); err != nil {
				return err
			}
			continue
		}
		if !utf8.Valid(line) || bytes.ContainsFunc(line, func(r rune) bool {
			return r != '\t' && unicode.IsControl(r)
		}) {
			if err := report.record(loc, loc.diagnostic(CodeSyntax), false); err != nil {
				return err
			}
			continue
		}
		trimmed := bytes.Trim(line, " \t")
		if skipTag != "" {
			if string(trimmed) == skipTag {
				skipTag = ""
			}
			continue
		}
		if inline != nil {
			if bytes.Equal(trimmed, []byte("</"+inline.loc.name+">")) {
				inline.body = body[:len(body)-len(previous)]
				if err := report.record(inline.loc, p.setMaterial(inline), false); err != nil {
					return err
				}
				inline, body = nil, nil
			} else if bytes.HasPrefix(trimmed, []byte("</")) ||
				(inline.loc.name != "auth-user-pass" && bytes.HasPrefix(trimmed, []byte("<"))) {
				loc.name = inline.loc.name
				if err := report.record(loc, loc.diagnostic(CodeSyntax), false); err != nil {
					return err
				}
			}
			continue
		}
		if bytes.HasPrefix(trimmed, []byte("<")) {
			name, ok := strings.CutSuffix(string(trimmed[1:]), ">")
			loc := knownLocation(name, number)
			var rejected error
			switch {
			case !ok:
				rejected = loc.diagnostic(CodeSyntax)
			case name == "connection":
				rejected = p.openConnection(loc)
			case name == "/connection":
				loc.name = "connection"
				rejected = p.closeConnection(number)
			case strings.HasPrefix(name, "/"):
				rejected = loc.diagnostic(CodeSyntax)
			default:
				rule, supported := directives[name]
				if !supported || !rule.inline {
					rejected = loc.diagnostic(CodeUnsupported)
				} else if p.block != nil && !rule.connection {
					rejected = loc.diagnostic(CodeScope)
				} else {
					inline, body = &material{loc: loc, inline: true}, remaining
					continue
				}
				// An unsupported inline section can still contain secrets.
				skipTag = "</" + name + ">"
			}
			if err := report.record(loc, rejected, false); err != nil {
				return err
			}
			continue
		}
		before := len(p.warnings)
		loc, rejected := p.readDirective(string(trimmed), number)
		if loc.line == 0 {
			continue
		}
		if err := report.record(loc, rejected, len(p.warnings) != before); err != nil {
			return err
		}
	}
	if inline != nil {
		if err := report.record(inline.loc, inline.loc.diagnostic(CodeSyntax), false); err != nil {
			return err
		}
	}
	if p.block != nil {
		return report.record(p.blockLoc, p.blockLoc.diagnostic(CodeSyntax), false)
	}
	return p.checkProtonDNSHooks(report)
}

func (p *parser) readDirective(line string, number int) (location, error) {
	fields, ok := words(line)
	loc := location{line: number}
	if len(fields) != 0 {
		loc = knownLocation(strings.TrimPrefix(fields[0], "--"), number)
	}
	if !ok {
		return loc, loc.diagnostic(CodeSyntax)
	}
	if len(fields) == 0 {
		return location{}, nil
	}
	rule, supported := directives[loc.name]
	if !supported && p.opts.ProtonVPNServerName != "" {
		rule, supported = protonDirectives[loc.name]
	}
	if !supported {
		return loc, loc.diagnostic(CodeUnsupported)
	}
	args := fields[1:]
	if len(args) < rule.min || len(args) > rule.max || loc.name == "connection" {
		return loc, loc.diagnostic(CodeSyntax)
	}
	if p.block != nil && !rule.connection {
		return loc, loc.diagnostic(CodeScope)
	}
	return loc, p.apply(loc, args)
}

func (p *parser) finish() error {
	if !p.tlsClient || !p.pull {
		return (location{name: "client"}).diagnostic(CodeRequired)
	}
	if !p.device {
		return (location{name: "dev"}).diagnostic(CodeRequired)
	}
	if len(p.remotes) == 0 && len(p.blocks) == 0 {
		return (location{name: "remote"}).diagnostic(CodeRequired)
	}
	if !tlscontrol.ValidVersions(p.cfg.TLS.MinVersion, p.cfg.TLS.MaxVersion) {
		return p.versionLocation.diagnostic(CodeConflict)
	}
	if err := p.setProtonServerIdentity(); err != nil {
		return err
	}
	if err := p.endpoints(); err != nil {
		return err
	}
	if p.attemptsPerRemote != 0 {
		p.cfg.Retry.MaxAttempts = len(p.cfg.Endpoints) * p.attemptsPerRemote
		if p.cfg.Retry.MaxAttempts > 1024 {
			return p.attemptsLocation.diagnostic(CodeLimit)
		}
	}
	if p.noCache.line != 0 && p.auth != nil && p.opts.Authentication.Credentials == nil {
		return p.noCache.diagnostic(CodeConflict)
	}
	return p.loadTLS()
}
