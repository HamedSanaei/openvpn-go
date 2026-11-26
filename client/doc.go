// Package client defines the OpenVPN client configuration and lifecycle.
//
// Connect verifies the server identity and establishes the OpenVPN TLS
// control channel and derives data keys. ControlInfo exposes the
// authenticated negotiation. Run forwards IP packets to a caller-owned tunnel.
package client
