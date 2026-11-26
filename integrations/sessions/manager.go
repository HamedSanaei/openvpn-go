// Package sessions owns independent OpenVPN clients and their tunnel leases.
package sessions

import (
	"context"
	"errors"
	"sync"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

var (
	ErrConfig    = errors.New("invalid session manager configuration")
	ErrCapacity  = errors.New("session quota exhausted")
	ErrDuplicate = errors.New("session identifier already in use")
	ErrClosed    = errors.New("session manager closed")
)

// Limits bound the active lease count and the sum of configured packet ceilings.
// Each lease gets one manager worker and its own bounded core client workers.
type Limits struct {
	Sessions    int
	PacketBytes int
}

// DeviceFactory opens a distinct tunnel and scoped configurator for one lease.
// The manager owns each returned device, including on a partial failure.
type DeviceFactory func(context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error)

type Manager struct {
	mu       sync.Mutex
	limits   Limits
	leases   map[string]*Lease
	reserved int
	closed   bool
	workers  sync.WaitGroup
}

type Lease struct {
	id     string
	size   int
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	client *client.Client
	result client.ErrorCode
	final  client.Stats
}

type Status struct {
	ID    string
	Done  bool
	Code  client.ErrorCode
	Stats client.Stats
}

func New(limits Limits) (*Manager, error) {
	if limits.Sessions < 1 || limits.Sessions > 64 || limits.PacketBytes < 1 ||
		limits.PacketBytes > limits.Sessions*transport.MaxPacketSize {
		return nil, ErrConfig
	}
	return &Manager{limits: limits, leases: make(map[string]*Lease)}, nil
}

// Start reserves capacity, validates and copies config through client.New
// and then prepares the tunnel asynchronously. ctx owns the lease lifetime.
func (m *Manager) Start(ctx context.Context, id string, config client.Config, open DeviceFactory) (*Lease, error) {
	if !validID(id) || open == nil || config.MaxPacketSize < 0 || config.MaxPacketSize > transport.MaxPacketSize {
		return nil, ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	size := config.MaxPacketSize
	if size == 0 {
		size = transport.DefaultPacketSize
	}
	m.mu.Lock()
	switch {
	case m.closed:
		m.mu.Unlock()
		return nil, ErrClosed
	case m.leases[id] != nil:
		m.mu.Unlock()
		return nil, ErrDuplicate
	case len(m.leases) >= m.limits.Sessions || m.reserved+size > m.limits.PacketBytes:
		m.mu.Unlock()
		return nil, ErrCapacity
	}
	ctx, cancel := context.WithCancel(ctx)
	lease := &Lease{id: id, size: size, cancel: cancel, done: make(chan struct{})}
	m.leases[id] = lease
	m.reserved += size
	m.workers.Add(1)
	m.mu.Unlock()

	c, err := client.New(config)
	if err != nil {
		m.finish(lease, nil, code(err))
		m.workers.Done()
		return nil, err
	}
	lease.mu.Lock()
	lease.client = c
	lease.mu.Unlock()
	go func() {
		defer m.workers.Done()
		result := run(ctx, c, open)
		if err := c.Close(); err != nil && result == "" {
			result = code(err)
		}
		m.finish(lease, c, result)
	}()
	return lease, nil
}

func run(ctx context.Context, c *client.Client, open DeviceFactory) (result client.ErrorCode) {
	if err := ctx.Err(); err != nil {
		return code(err)
	}
	device, configure, err := open(ctx)
	if device != nil {
		defer func() {
			if err := device.Close(); err != nil && result == "" {
				result = client.CodeTunnel
			}
		}()
	}
	if ctx.Err() != nil {
		return code(ctx.Err())
	}
	if err != nil || device == nil {
		return client.CodeTunnel
	}
	if err := c.Connect(ctx); err != nil {
		return code(err)
	}
	return code(c.RunConfigured(ctx, device, configure))
}

func (m *Manager) finish(lease *Lease, c *client.Client, result client.ErrorCode) {
	lease.cancel()
	lease.mu.Lock()
	if c != nil {
		lease.final = c.Stats()
	}
	lease.client, lease.result = nil, result
	m.mu.Lock()
	delete(m.leases, lease.id)
	m.reserved -= lease.size
	close(lease.done)
	m.mu.Unlock()
	lease.mu.Unlock()
}

// Lookup returns the current lease for id. Completed leases remain readable
// through the handle returned by Start and do not consume manager capacity.
func (m *Manager) Lookup(id string) (*Lease, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	lease, ok := m.leases[id]
	return lease, ok
}

func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	for _, lease := range m.leases {
		lease.cancel()
	}
	m.mu.Unlock()
	m.workers.Wait()
}

// Stop requests cancellation. Wait joins network and device cleanup.
func (l *Lease) Stop() { l.cancel() }

// Done closes after network and device teardown and release of the quota.
func (l *Lease) Done() <-chan struct{} { return l.done }

func (l *Lease) Wait(ctx context.Context) (Status, error) {
	select {
	case <-l.done:
		return l.Status(), nil
	case <-ctx.Done():
		return Status{}, ctx.Err()
	}
}

func (l *Lease) Status() Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	status := Status{ID: l.id, Code: l.result, Stats: l.final}
	if l.client != nil {
		status.Stats = l.client.Stats()
	}
	select {
	case <-l.done:
		status.Done = true
	default:
	}
	return status
}

func code(err error) client.ErrorCode {
	var failure *client.Error
	switch {
	case err == nil:
		return ""
	case errors.As(err, &failure):
		return failure.Code
	case errors.Is(err, context.Canceled):
		return client.CodeCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return client.CodeTimeout
	default:
		return client.CodeTunnel
	}
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 48 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
