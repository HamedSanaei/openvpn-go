package xray

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/hamedsanaei/openvpn-go/tunnel"
)

var ErrDNSUnavailable = errors.New("VPN DNS server unavailable on the acknowledged tunnel")

// ErrDNSCleanup means a generation's owned DNS socket could not be closed.
var ErrDNSCleanup = errors.New("VPN DNS socket cleanup failed")

// DNSDialer opens an explicitly selected numeric server through the tunnel.
// It must bind the socket to the generation's VPN path and honor cancellation.
// The caller handles DNS wire framing, domain routing, and encrypted DNS.
type DNSDialer func(context.Context, string, netip.AddrPort) (net.Conn, error)

type dnsScope struct {
	ctx        context.Context
	generation uint64
	config     tunnel.DNSConfig

	mu          sync.Mutex
	closed      bool
	dials       sync.WaitGroup
	failed      atomic.Bool
	connections map[*dnsConn]struct{}
}

// ActiveDNS returns a detached snapshot for the current acknowledged
// generation. The caller selects a server using ResolveDomains and transport.
func (a *Adapter) ActiveDNS() (generation uint64, config tunnel.DNSConfig, active bool) {
	s := a.dns.Load()
	if s == nil || s.ctx.Err() != nil {
		return 0, tunnel.DNSConfig{}, false
	}
	return s.generation, s.config.Clone(), true
}

// DialDNS opens UDP or TCP only to a server announced by the active
// generation. TLS-based DNS endpoints require TCP. On disconnect all
// returned sockets close before the caller's tunnel rollback runs. An
// authorized dial reports its caller's cancellation or deadline, even
// if its generation retires in flight. Requests for already retired
// generations and retirement without caller cancellation are unavailable.
// A failed close on a partial dial adds ErrDNSCleanup to that cause.
func (a *Adapter) DialDNS(ctx context.Context, generation uint64, network string, server netip.AddrPort) (net.Conn, error) {
	s := a.dns.Load()
	if s == nil || s.generation != generation || (network != "udp" && network != "tcp") {
		return nil, ErrDNSUnavailable
	}
	if !slices.ContainsFunc(s.config.Servers, func(group tunnel.DNSServer) bool {
		return slices.Contains(group.Addresses, server) &&
			(network == "tcp" || group.Transport == "" || group.Transport == tunnel.DNSPlain)
	}) {
		return nil, ErrDNSUnavailable
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, ErrDNSUnavailable
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.dials.Add(1)
	s.mu.Unlock()
	defer s.dials.Done()

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	conn, err := a.options.DNSDialer(dialCtx, network, server)
	s.mu.Lock()
	if err != nil || conn == nil || s.closed || s.ctx.Err() != nil || dialCtx.Err() != nil {
		s.mu.Unlock()
		cleanupFailed := conn != nil && s.recordClose(conn.Close())
		cause := ctx.Err()
		if cause == nil {
			cause = ErrDNSUnavailable
		}
		if cleanupFailed {
			cause = errors.Join(cause, ErrDNSCleanup)
		}
		return nil, cause
	}
	wrapped := &dnsConn{Conn: conn, scope: s}
	s.connections[wrapped] = struct{}{}
	s.mu.Unlock()
	return wrapped, nil
}

func (s *dnsScope) recordClose(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	s.failed.Store(true)
	return true
}

func (s *dnsScope) close() bool {
	s.mu.Lock()
	s.closed = true
	connections := s.connections
	s.connections = nil
	s.mu.Unlock()
	s.dials.Wait()
	for c := range connections {
		c.Close()
	}
	return s.failed.Load()
}

type dnsConn struct {
	net.Conn
	scope    *dnsScope
	once     sync.Once
	closeErr error
}

func (c *dnsConn) Read(p []byte) (int, error) {
	if c.scope.ctx.Err() != nil {
		return 0, ErrDNSUnavailable
	}
	n, err := c.Conn.Read(p)
	if c.scope.ctx.Err() != nil {
		return 0, ErrDNSUnavailable
	}
	return n, err
}

func (c *dnsConn) Write(p []byte) (int, error) {
	if c.scope.ctx.Err() != nil {
		return 0, ErrDNSUnavailable
	}
	return c.Conn.Write(p)
}

func (c *dnsConn) Close() error {
	c.once.Do(func() {
		if err := c.Conn.Close(); c.scope.recordClose(err) {
			c.closeErr = ErrDNSCleanup
		} else if err != nil {
			c.closeErr = net.ErrClosed
		}
		c.scope.mu.Lock()
		delete(c.scope.connections, c)
		c.scope.mu.Unlock()
	})
	return c.closeErr
}
