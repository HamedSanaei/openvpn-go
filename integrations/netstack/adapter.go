// Package netstack implements an unprivileged IP packet device with
// isolated TCP, UDP and DNS sockets for an OpenVPN Go client.
package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	nic         = 1
	packetQueue = 64
	dialBudget  = 10 * time.Second
)

var (
	ErrConfig      = errors.New("invalid userspace network configuration")
	ErrPacket      = errors.New("invalid userspace IP packet")
	ErrSocketLimit = errors.New("userspace socket limit reached")
)

// Config supplies assigned addresses and numeric DNS servers. Configure at
// most one address per family. MTU defaults to 1500 and MaxSockets to 64.
type Config struct {
	Addresses  []netip.Prefix
	DNSServers []netip.AddrPort
	MTU        uint32
	MaxSockets int
}

// Adapter owns an independent network stack. ReadPacket and WritePacket
// satisfy the core tunnel.PacketConn contract without OS routes or sockets.
type Adapter struct {
	stack  *stack.Stack
	link   *channel.Endpoint
	mtu    int
	dns    []netip.AddrPort
	life   context.Context
	cancel context.CancelFunc
	slots  chan struct{}

	mu      sync.Mutex
	closed  bool
	dials   sync.WaitGroup
	sockets map[*socket]struct{}
	once    sync.Once
}

func New(config Config) (*Adapter, error) {
	if config.MTU == 0 {
		config.MTU = 1500
	}
	if config.MaxSockets == 0 {
		config.MaxSockets = 64
	}
	if len(config.Addresses) == 0 || len(config.Addresses) > 2 || len(config.DNSServers) > 8 ||
		config.MTU < 576 || config.MTU > 9000 || config.MaxSockets < 1 || config.MaxSockets > 256 {
		return nil, ErrConfig
	}
	var v4, v6 bool
	for _, prefix := range config.Addresses {
		addr := prefix.Addr()
		if !prefix.IsValid() || !usableIP(addr) || addr.Is4() && v4 || addr.Is6() && (v6 || config.MTU < 1280) {
			return nil, ErrConfig
		}
		v4, v6 = v4 || addr.Is4(), v6 || addr.Is6()
	}
	for i, dns := range config.DNSServers {
		if dns.Port() == 0 || !usableIP(dns.Addr()) || dns.Addr().Is4() && !v4 ||
			dns.Addr().Is6() && !v6 || slices.Contains(config.DNSServers[:i], dns) {
			return nil, ErrConfig
		}
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	link := channel.New(packetQueue, config.MTU, "")
	life, cancel := context.WithCancel(context.Background())
	a := &Adapter{stack: s, link: link, mtu: int(config.MTU), dns: slices.Clone(config.DNSServers),
		life: life, cancel: cancel, slots: make(chan struct{}, config.MaxSockets), sockets: make(map[*socket]struct{})}
	if err := s.CreateNIC(nic, link); err != nil {
		a.Close()
		return nil, ErrConfig
	}
	for _, prefix := range config.Addresses {
		addr := tcpip.ProtocolAddress{
			Protocol: protocol(prefix.Addr()),
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address: tcpip.AddrFromSlice(prefix.Addr().AsSlice()), PrefixLen: prefix.Bits(),
			},
		}
		if err := s.AddProtocolAddress(nic, addr, stack.AddressProperties{}); err != nil {
			a.Close()
			return nil, ErrConfig
		}
	}
	var routes []tcpip.Route
	if v4 {
		routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nic})
	}
	if v6 {
		routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nic})
	}
	s.SetRouteTable(routes)
	return a, nil
}

func usableIP(addr netip.Addr) bool {
	return addr.IsValid() && !addr.Is4In6() && addr.Zone() == "" &&
		(addr.IsGlobalUnicast() || addr.IsLinkLocalUnicast())
}

func protocol(addr netip.Addr) tcpip.NetworkProtocolNumber {
	if addr.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

func (a *Adapter) ReadPacket(ctx context.Context, dst []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	pkt := a.link.ReadContext(ctx)
	if pkt == nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return 0, net.ErrClosed
	}
	defer pkt.DecRef()
	if pkt.Size() > len(dst) {
		return 0, io.ErrShortBuffer
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, part := range pkt.AsSlices() {
		n += copy(dst[n:], part)
	}
	return n, nil
}

func (a *Adapter) WritePacket(ctx context.Context, packet []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(packet) < 20 || len(packet) > a.mtu {
		return ErrPacket
	}
	var proto tcpip.NetworkProtocolNumber
	switch packet[0] >> 4 {
	case 4:
		headerLen := int(packet[0]&15) * 4
		if headerLen < 20 || headerLen > len(packet) || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
			return ErrPacket
		}
		proto = ipv4.ProtocolNumber
	case 6:
		if len(packet) < 40 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) {
			return ErrPacket
		}
		proto = ipv6.ProtocolNumber
	default:
		return ErrPacket
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(packet))})
	defer pkt.DecRef()
	a.link.InjectInbound(proto, pkt)
	return nil
}

// DialContext opens an in-stack socket to a numeric IP and port. Use tcp or
// udp. The setup deadline is capped at ten seconds. The caller owns Close.
func (a *Adapter) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dest, err := netip.ParseAddrPort(address)
	if err != nil || dest.Port() == 0 || !usableIP(dest.Addr()) || network != "tcp" && network != "udp" {
		return nil, ErrConfig
	}
	return a.dial(ctx, network, dest)
}

func (a *Adapter) dial(ctx context.Context, network string, dest netip.AddrPort) (net.Conn, error) {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	select {
	case a.slots <- struct{}{}:
	default:
		a.mu.Unlock()
		return nil, ErrSocketLimit
	}
	a.dials.Add(1)
	a.mu.Unlock()
	defer a.dials.Done()

	dialCtx, cancel := context.WithTimeout(ctx, dialBudget)
	defer cancel()
	stop := context.AfterFunc(a.life, cancel)
	defer stop()
	addr := tcpip.FullAddress{NIC: nic, Addr: tcpip.AddrFromSlice(dest.Addr().AsSlice()), Port: dest.Port()}
	proto := protocol(dest.Addr())
	var conn net.Conn
	var err error
	if network == "tcp" {
		var tcpConn *gonet.TCPConn
		tcpConn, err = gonet.DialContextTCP(dialCtx, a.stack, addr, proto)
		if tcpConn != nil {
			conn = tcpConn
		}
	} else {
		var udpConn *gonet.UDPConn
		udpConn, err = gonet.DialUDP(a.stack, nil, &addr, proto)
		if udpConn != nil {
			conn = udpConn
		}
	}
	a.mu.Lock()
	if err == nil {
		err = dialCtx.Err()
	}
	if a.closed {
		err = net.ErrClosed
	}
	if err != nil {
		a.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		<-a.slots
		return nil, err
	}
	s := &socket{Conn: conn, owner: a}
	a.sockets[s] = struct{}{}
	a.mu.Unlock()
	return s, nil
}

type socket struct {
	net.Conn
	owner *Adapter
	once  sync.Once
	err   error
}

func (s *socket) Close() error {
	s.once.Do(func() {
		s.err = s.Conn.Close()
		s.owner.mu.Lock()
		delete(s.owner.sockets, s)
		s.owner.mu.Unlock()
		<-s.owner.slots
	})
	return s.err
}

// Close interrupts packet reads and dials and closes the owned sockets.
func (a *Adapter) Close() error {
	a.once.Do(func() {
		a.mu.Lock()
		a.closed = true
		active := a.sockets
		a.sockets = nil
		a.mu.Unlock()
		a.cancel()
		a.link.Close()
		a.dials.Wait()
		for conn := range active {
			conn.Close()
		}
		a.stack.Destroy()
	})
	return nil
}
