package profile

import (
	"bytes"
	"cmp"
	"io"
	"slices"

	"github.com/hamedsanaei/openvpn-go/client"
)

// Capability describes whether a directive can be used by this parser.
type Capability string

const (
	Supported      Capability = "supported"
	Ignored        Capability = "ignored"
	Rejected       Capability = "rejected"
	PolicyDisabled Capability = "policy-disabled"
)

// CapabilityEntry includes only registry names and stable diagnostic codes.
// An unknown directive has an empty Directive field.
type CapabilityEntry struct {
	Line       int        `json:"line"`
	Directive  string     `json:"directive,omitempty"`
	Capability Capability `json:"capability"`
	Code       Code       `json:"code,omitempty"`
}

type Report struct {
	Entries []CapabilityEntry `json:"entries"`
}

// Inspect classifies all directive lines it can read within the normal profile
// limits. It never opens references, interprets inline material or dials a
// peer. Parse still validates required directives and referenced material.
func Inspect(r io.Reader) (Report, error) {
	return InspectWithOptions(r, Options{})
}

// InspectWithOptions classifies a profile under the configured import policy.
// It uses the profile syntax options and does not load files or credentials.
func InspectWithOptions(r io.Reader, opts Options) (Report, error) {
	if err := opts.ValidateImportPolicy(); err != nil {
		return Report{}, err
	}
	if r == nil {
		return Report{}, (location{}).diagnostic(CodeRead)
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxProfile+1))
	defer clear(raw)
	if err != nil {
		return Report{}, (location{}).diagnostic(CodeRead)
	}
	if len(raw) > maxProfile {
		return Report{}, (location{}).diagnostic(CodeLimit)
	}
	p := parser{opts: Options{
		ProtonVPNServerName: opts.ProtonVPNServerName, ProtonVPNVerifyIP: opts.ProtonVPNVerifyIP,
		ExpressVPNManual: opts.ExpressVPNManual, AccessServerName: opts.AccessServerName, PritunlServerName: opts.PritunlServerName, AllowPasswordOnly: opts.AllowPasswordOnly,
	}, cfg: client.Config{TLS: &client.TLSConfig{}}}
	report := Report{Entries: []CapabilityEntry{}}
	err = p.read(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")), &report)
	slices.SortStableFunc(report.Entries, func(a, b CapabilityEntry) int { return cmp.Compare(a.Line, b.Line) })
	return report, err
}

func (r *Report) record(loc location, err error, ignored bool) error {
	if r == nil {
		return err
	}
	entry := CapabilityEntry{Line: loc.line, Directive: loc.name, Capability: Supported}
	if err != nil {
		diag := err.(*Diagnostic) // The profile parser returns redacted diagnostics.
		entry.Code = diag.Code
		entry.Capability = Rejected
		if diag.Code == CodeUnsupported && loc.name != "" {
			entry.Capability = PolicyDisabled
		}
	} else if ignored {
		entry.Capability, entry.Code = Ignored, CodeIgnored
	}
	r.Entries = append(r.Entries, entry)
	return nil
}
