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
		opts: opts, cfg: client.Config{TLS: &client.TLSConfig{}},
		filesLeft: maxFileBytes, loaded: make(map[*material][]byte),
	}
	if err := p.read(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))); err != nil {
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
	opts            Options
	cfg             client.Config
	identity        client.X509Name
	versionLocation location
	warnings        []Diagnostic
	tlsClient       bool
	pull            bool
	device          bool

	defaults connection
	remotes  []remote
	blocks   []connection
	block    *connection
	blockLoc location

	ca, cert, key, auth *material
	loaded              map[*material][]byte
	filesLeft           int
}

func (p *parser) read(remaining []byte) error {
	var inline *material
	var body []byte
	for number := 1; len(remaining) != 0; number++ {
		previous := remaining
		line, rest, _ := bytes.Cut(remaining, []byte{'\n'})
		remaining = rest
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) > maxLine {
			return (location{line: number}).diagnostic(CodeLimit)
		}
		if !utf8.Valid(line) || bytes.ContainsFunc(line, func(r rune) bool {
			return r != '\t' && unicode.IsControl(r)
		}) {
			return (location{line: number}).diagnostic(CodeSyntax)
		}
		trimmed := bytes.Trim(line, " \t")
		if inline != nil {
			if bytes.Equal(trimmed, []byte("</"+inline.loc.name+">")) {
				inline.body = body[:len(body)-len(previous)]
				if err := p.setMaterial(inline); err != nil {
					return err
				}
				inline, body = nil, nil
			} else if bytes.HasPrefix(trimmed, []byte("</")) ||
				(inline.loc.name != "auth-user-pass" && bytes.HasPrefix(trimmed, []byte("<"))) {
				return (location{line: number, name: inline.loc.name}).diagnostic(CodeSyntax)
			}
			continue
		}
		if bytes.HasPrefix(trimmed, []byte("<")) {
			name, ok := strings.CutSuffix(string(trimmed[1:]), ">")
			loc := knownLocation(name, number)
			switch {
			case !ok:
				return loc.diagnostic(CodeSyntax)
			case name == "connection":
				if err := p.openConnection(loc); err != nil {
					return err
				}
			case name == "/connection":
				if err := p.closeConnection(number); err != nil {
					return err
				}
			case strings.HasPrefix(name, "/"):
				return loc.diagnostic(CodeSyntax)
			default:
				rule, supported := directives[name]
				if !supported || !rule.inline {
					return loc.diagnostic(CodeUnsupported)
				}
				if p.block != nil && !rule.connection {
					return loc.diagnostic(CodeScope)
				}
				inline, body = &material{loc: loc, inline: true}, remaining
			}
			continue
		}
		if err := p.readDirective(string(trimmed), number); err != nil {
			return err
		}
	}
	if inline != nil {
		return inline.loc.diagnostic(CodeSyntax)
	}
	if p.block != nil {
		return p.blockLoc.diagnostic(CodeSyntax)
	}
	return nil
}

func (p *parser) readDirective(line string, number int) error {
	fields, ok := words(line)
	loc := location{line: number}
	if len(fields) != 0 {
		loc = knownLocation(strings.TrimPrefix(fields[0], "--"), number)
	}
	if !ok {
		return loc.diagnostic(CodeSyntax)
	}
	if len(fields) == 0 {
		return nil
	}
	rule, supported := directives[loc.name]
	if !supported {
		return loc.diagnostic(CodeUnsupported)
	}
	args := fields[1:]
	if len(args) < rule.min || len(args) > rule.max || loc.name == "connection" {
		return loc.diagnostic(CodeSyntax)
	}
	if p.block != nil && !rule.connection {
		return loc.diagnostic(CodeScope)
	}
	return p.apply(loc, args)
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
	if err := p.endpoints(); err != nil {
		return err
	}
	return p.loadTLS()
}
