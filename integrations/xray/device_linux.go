//go:build linux

package xray

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
	"golang.org/x/sys/unix"
)

// OpenDevice attaches to an existing Linux TUN. The host configures its
// owner, addresses, MTU and routing. The caller owns the returned handle.
func OpenDevice(name string, addresses Addresses) (tunnel.PacketConn, error) {
	if !addresses.valid() || name == "" {
		return nil, ErrTunnelConfig
	}
	iface, err := net.InterfaceByName(name)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.MTU < 68 || iface.MTU > transport.MaxPacketSize {
		return nil, ErrTunnelConfig
	}
	local, err := iface.Addrs()
	if err != nil || !ownsAddresses(local, addresses) {
		return nil, ErrTunnelConfig
	}
	req, err := unix.NewIfreq(name)
	if err != nil {
		return nil, ErrTunnelConfig
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrTunnelConfig
	}
	req.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, req); err != nil {
		unix.Close(fd)
		return nil, ErrTunnelConfig
	}
	file := os.NewFile(uintptr(fd), "openvpn tunnel")
	if err := file.SetDeadline(time.Time{}); err != nil {
		file.Close()
		return nil, ErrTunnelConfig
	}
	return &tunDevice{file: file, inbound: make([]byte, transport.MaxPacketSize+1)}, nil
}

// BindDNSDevice creates a numeric DNS dialer with mandatory Linux interface
// binding. The caller provisions the VPN interface and its routes.
func BindDNSDevice(name string) DNSDialer {
	return func(ctx context.Context, network string, server netip.AddrPort) (net.Conn, error) {
		if name == "" || !server.IsValid() || server.Port() == 0 || (network != "udp" && network != "tcp") {
			return nil, ErrDNSUnavailable
		}
		dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
			var bindErr error
			if err := raw.Control(func(fd uintptr) {
				bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
			}); err != nil {
				return err
			}
			return bindErr
		}}
		return dialer.DialContext(ctx, network, server.String())
	}
}

func ownsAddresses(local []net.Addr, expected Addresses) bool {
	v4, v6 := !expected.IPv4.IsValid(), !expected.IPv6.IsValid()
	for _, address := range local {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil {
			v4 = v4 || prefix.Addr() == expected.IPv4
			v6 = v6 || prefix == expected.IPv6
		}
	}
	return v4 && v6
}

type tunDevice struct {
	file    *os.File
	inbound []byte
}

func (d *tunDevice) Close() error { return d.file.Close() }

func (d *tunDevice) ReadPacket(ctx context.Context, packet []byte) (int, error) {
	n, err := tunIO(ctx, d.file.SetReadDeadline, func() (int, error) { return d.file.Read(d.inbound) })
	defer clear(d.inbound[:n])
	if err != nil {
		return 0, err
	}
	if n == len(d.inbound) || n > len(packet) {
		return 0, io.ErrShortBuffer
	}
	return copy(packet, d.inbound[:n]), nil
}

func (d *tunDevice) WritePacket(ctx context.Context, packet []byte) error {
	n, err := tunIO(ctx, d.file.SetWriteDeadline, func() (int, error) { return d.file.Write(packet) })
	if err == nil && n != len(packet) {
		return io.ErrShortWrite
	}
	return err
}

func tunIO(ctx context.Context, deadline func(time.Time) error, ioCall func() (int, error)) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if ctx.Done() == nil {
		return ioCall()
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		deadline(time.Now())
	})
	n, err := ioCall()
	if !stop() {
		<-interrupted
		deadline(time.Time{})
	}
	if errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() != nil {
		return 0, ctx.Err()
	}
	return n, err
}
