// Package profile will parse and validate OpenVPN client profiles.
//
// Parsing is separate from dialing. Unsupported security-sensitive directives
// must be reported explicitly; parsing must never execute profile scripts.
package profile
