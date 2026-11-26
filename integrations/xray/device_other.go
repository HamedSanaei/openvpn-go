//go:build !linux

package xray

import "github.com/hamedsanaei/openvpn-go/tunnel"

// OpenDevice attaches to a Linux TUN on supported hosts.
func OpenDevice(string, Addresses) (tunnel.PacketConn, error) {
	return nil, ErrTunnelConfig
}
