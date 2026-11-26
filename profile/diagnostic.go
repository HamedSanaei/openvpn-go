package profile

import "fmt"

// Code classifies a profile error or warning.
type Code string

const (
	CodeRead        Code = "profile_read"
	CodeLimit       Code = "limit_exceeded"
	CodeSyntax      Code = "invalid_syntax"
	CodeValue       Code = "invalid_value"
	CodeUnsupported Code = "unsupported_directive"
	CodeScope       Code = "invalid_scope"
	CodeConflict    Code = "conflicting_directive"
	CodeRequired    Code = "missing_required"
	CodeFile        Code = "file_unavailable"
	CodeMaterial    Code = "invalid_material"
	CodeIgnored     Code = "ignored_directive"
)

// Diagnostic identifies a problem by code and 1-based profile line. A zero
// line describes the profile as a whole. Directive is a fixed registry name
// when known. Diagnostics never contain raw tokens, file paths or secrets.
type Diagnostic struct {
	Code      Code
	Line      int
	Directive string
}

func (d Diagnostic) Error() string {
	message := fmt.Sprintf("ovpn profile line %d: %s", d.Line, d.Code)
	if d.Line == 0 {
		message = "ovpn profile: " + string(d.Code)
	}
	if d.Directive != "" {
		message += " (" + d.Directive + ")"
	}
	return message
}

type location struct {
	line int
	name string
}

func (l location) diagnostic(code Code) *Diagnostic {
	return &Diagnostic{Code: code, Line: l.line, Directive: l.name}
}
