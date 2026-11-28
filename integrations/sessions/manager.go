// Package sessions owns independent OpenVPN clients and their tunnel leases.
package sessions

import (
	"context"
	"errors"
	"math"
	"net"
	"sync"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/control"
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

// ResourceLimits caps estimated packet-buffer bytes and optionally file
// descriptors. TLS, kernel sockets, stacks and other heap are outside this
// estimate. One descriptor is reserved for each transport.
type ResourceLimits struct {
	BufferBytes     int64
	FileDescriptors int
}

// AdapterReservation adds declared adapter bounds to the core estimate.
type AdapterReservation struct {
	BufferBytes     int64
	FileDescriptors int
}

// Usage reports reservations for leases until their cleanup completes.
type Usage struct {
	Sessions        int
	PacketBytes     int
	BufferBytes     int64
	FileDescriptors int
}

// DeviceFactory opens a distinct tunnel and scoped configurator for one lease.
// The manager owns each returned device, including on a partial failure.
type DeviceFactory func(context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error)

type Manager struct {
	mu        sync.Mutex
	limits    Limits
	leases    map[string]*Lease
	resources ResourceLimits
	usage     Usage
	closed    bool
	workers   sync.WaitGroup
}

type Lease struct {
	id       string
	reserved Usage
	cancel   context.CancelFunc
	done     chan struct{}
	mu       sync.Mutex
	client   *client.Client
	result   client.ErrorCode
	cleanup  CleanupStatus
	final    client.Stats
}

type Status struct {
	ID    string
	Done  bool
	Code  client.ErrorCode
	Stats client.Stats
	// Cleanup reports failures independently of the lease's stop reason.
	Cleanup CleanupStatus
}

// CleanupStatus describes which owned resource failed to close. Status keeps
// these flags after releasing the lease reservation and its identifier.
type CleanupStatus struct {
	DeviceFailed bool
	ClientFailed bool
}

func New(limits Limits) (*Manager, error) {
	return newManager(limits, ResourceLimits{math.MaxInt64, math.MaxInt}, 64)
}

// NewWithResources permits up to 4,096 leases with an explicit buffer
// reservation budget. A zero descriptor limit uses only the session bound.
func NewWithResources(limits Limits, resources ResourceLimits) (*Manager, error) {
	if resources.BufferBytes <= 0 || resources.FileDescriptors < 0 {
		return nil, ErrConfig
	}
	if resources.FileDescriptors == 0 {
		resources.FileDescriptors = math.MaxInt
	}
	return newManager(limits, resources, 4096)
}

func newManager(limits Limits, resources ResourceLimits, maxSessions int) (*Manager, error) {
	if limits.Sessions < 1 || limits.Sessions > maxSessions || limits.PacketBytes < 1 ||
		limits.PacketBytes > limits.Sessions*transport.MaxPacketSize {
		return nil, ErrConfig
	}
	return &Manager{limits: limits, resources: resources, leases: make(map[string]*Lease)}, nil
}

// Start reserves capacity, validates and copies config through client.New
// and then prepares the tunnel asynchronously. ctx owns the lease lifetime.
func (m *Manager) Start(ctx context.Context, id string, config client.Config, open DeviceFactory) (*Lease, error) {
	return m.StartWithResources(ctx, id, config, AdapterReservation{}, open)
}

// StartWithResources starts a lease with separately estimated adapter usage.
func (m *Manager) StartWithResources(ctx context.Context, id string, config client.Config, adapter AdapterReservation, open DeviceFactory) (*Lease, error) {
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
	reservation, err := leaseUsage(config, size, adapter)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	switch {
	case m.closed:
		m.mu.Unlock()
		return nil, ErrClosed
	case m.leases[id] != nil:
		m.mu.Unlock()
		return nil, ErrDuplicate
	case len(m.leases) >= m.limits.Sessions || reservation.PacketBytes > m.limits.PacketBytes-m.usage.PacketBytes ||
		reservation.BufferBytes > m.resources.BufferBytes-m.usage.BufferBytes ||
		reservation.FileDescriptors > m.resources.FileDescriptors-m.usage.FileDescriptors:
		m.mu.Unlock()
		return nil, ErrCapacity
	}
	ctx, cancel := context.WithCancel(ctx)
	lease := &Lease{id: id, reserved: reservation, cancel: cancel, done: make(chan struct{})}
	m.leases[id] = lease
	m.usage.PacketBytes += reservation.PacketBytes
	m.usage.BufferBytes += reservation.BufferBytes
	m.usage.FileDescriptors += reservation.FileDescriptors
	m.workers.Add(1)
	m.mu.Unlock()

	c, err := client.New(config)
	if err != nil {
		m.finish(lease, nil, code(err), CleanupStatus{})
		m.workers.Done()
		return nil, err
	}
	lease.mu.Lock()
	lease.client = c
	lease.mu.Unlock()
	go func() {
		defer m.workers.Done()
		result, cleanup := run(ctx, c, open)
		if err := c.Close(); err != nil {
			cleanup.ClientFailed = true
			if result == "" {
				result = code(err)
			}
		}
		m.finish(lease, c, result, cleanup)
	}()
	return lease, nil
}

func run(ctx context.Context, c *client.Client, open DeviceFactory) (result client.ErrorCode, cleanup CleanupStatus) {
	if err := ctx.Err(); err != nil {
		return code(err), cleanup
	}
	device, configure, err := open(ctx)
	if device != nil {
		defer func() {
			if err := device.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				cleanup.DeviceFailed = true
				if result == "" {
					result = client.CodeTunnel
				}
			}
		}()
	}
	if ctx.Err() != nil {
		return code(ctx.Err()), cleanup
	}
	if err != nil || device == nil {
		return client.CodeTunnel, cleanup
	}
	if err := c.Connect(ctx); err != nil {
		return code(err), cleanup
	}
	return code(c.RunConfigured(ctx, device, configure)), cleanup
}

func (m *Manager) finish(lease *Lease, c *client.Client, result client.ErrorCode, cleanup CleanupStatus) {
	lease.cancel()
	lease.mu.Lock()
	if c != nil {
		lease.final = c.Stats()
	}
	lease.client, lease.result, lease.cleanup = nil, result, cleanup
	m.mu.Lock()
	delete(m.leases, lease.id)
	m.usage.PacketBytes -= lease.reserved.PacketBytes
	m.usage.BufferBytes -= lease.reserved.BufferBytes
	m.usage.FileDescriptors -= lease.reserved.FileDescriptors
	close(lease.done)
	m.mu.Unlock()
	lease.mu.Unlock()
}

func leaseUsage(cfg client.Config, size int, adapter AdapterReservation) (Usage, error) {
	if adapter.BufferBytes < 0 || adapter.FileDescriptors < 0 || adapter.FileDescriptors == math.MaxInt {
		return Usage{}, ErrConfig
	}
	queue := cfg.ReceiveQueueSize
	if queue <= 0 || queue > control.MaxDataQueueSize {
		queue = control.DefaultDataQueueSize
	}
	// Two packet queues, bounded working frames and native UDP scratch.
	core := int64(2*queue+6)*int64(size) + transport.MaxPacketSize + 1
	for _, endpoint := range cfg.Endpoints {
		if endpoint.ExpressVPNFragmentSize != 0 {
			core += 32 * (int64(size) + 1)
			break
		}
	}
	if adapter.BufferBytes > math.MaxInt64-core {
		return Usage{}, ErrConfig
	}
	return Usage{PacketBytes: size, BufferBytes: core + adapter.BufferBytes, FileDescriptors: 1 + adapter.FileDescriptors}, nil
}

// Usage returns the current reservation totals.
func (m *Manager) Usage() Usage {
	m.mu.Lock()
	defer m.mu.Unlock()
	usage := m.usage
	usage.Sessions = len(m.leases)
	return usage
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
	status := Status{ID: l.id, Code: l.result, Stats: l.final, Cleanup: l.cleanup}
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
