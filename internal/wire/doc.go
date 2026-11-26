// Package wire implements OpenVPN packet framing and wire-level codecs.
//
// It owns opcode/key-id parsing, UDP packet boundaries and TCP length framing.
// It must remain bounded and safe for arbitrary network input.
package wire
