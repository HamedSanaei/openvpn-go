package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/observability"
	"github.com/hamedsanaei/openvpn-go/internal/session"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

// Run forwards complete IP packets between the authenticated session and
// device. It borrows device, which remains open on return. Run reconnects
// after transport loss under the configured retry policy and resumes
// forwarding on the same device. Cancel the context or call Close to stop.
func (c *Client) Run(ctx context.Context, device tunnel.PacketConn) error {
	return c.RunConfigured(ctx, device, nil)
}

// TunnelGeneration identifies one authenticated connection. Rekeying within
// that connection keeps the same generation number.
type TunnelGeneration struct {
	Number   uint64
	Endpoint Endpoint
	Control  ControlInfo
}

// TunnelConfigurer prepares caller-owned tunnel state for one generation.
// Returning nil error acknowledges the configuration and permits forwarding.
// A returned rollback is called exactly once after forwarding stops or if
// the setup fails. It must restore any changes made even on partial failure.
// The context ends on disconnect or stop. Both callbacks must return
// promptly and must not call Client.Close synchronously.
// A setup error can report uncertain teardown independently of its cause by
// implementing TunnelCleanupFailed() bool. The client reports that state as
// ErrTunnelCleanup and blocks reuse of the client. Reconcile the host
// resources before opening a new client.
type TunnelConfigurer func(context.Context, TunnelGeneration) (rollback func(), err error)

// ErrTunnelCleanup indicates that the tunnel configurator could not release
// all resources after setup. Run reports it alongside the primary outcome.
var ErrTunnelCleanup = errors.New("tunnel configuration cleanup failed")

// RunConfigured calls configure before any forwarding on each authenticated
// connection. A rejection stops Run. RunConfigured borrows the packet device.
func (c *Client) RunConfigured(ctx context.Context, device tunnel.PacketConn, configure TunnelConfigurer) error {
	if device == nil {
		return configError("tunnel")
	}
	c.mu.Lock()
	active := c.liveConnection()
	if err := c.operationError(ctx, "run"); err != nil {
		c.mu.Unlock()
		return err
	}
	if c.run != nil || c.attempt != nil {
		c.mu.Unlock()
		return &Error{Op: "run", Code: CodeBusy}
	}
	if active == nil {
		c.mu.Unlock()
		return &Error{Op: "run", Code: CodeNotConnected}
	}

	runCtx, cancel := context.WithCancel(ctx)
	run := &operation{cancel: cancel, done: make(chan struct{})}
	c.run = run
	c.mu.Unlock()
	defer c.finish(run, &c.run)

	inbound := make([]byte, c.config.MaxPacketSize)
	outbound := make([]byte, c.config.MaxPacketSize)
	for {
		result := c.forwardGeneration(runCtx, device, active, configure, inbound, outbound)
		result, stopped := c.endSession(runCtx, active, result)
		if result.tunnelCleanupFailed {
			if stopped == nil {
				stopped = result.err
			}
			return errors.Join(stopped, ErrTunnelCleanup)
		}
		if stopped != nil {
			return stopped
		}
		if !result.fromSession || !canRecover(result.err.Code) || c.config.Retry.DisableReconnect {
			return result.err
		}
		next := (active.position + 1) % len(c.order)
		if result.sameEndpoint || result.err.Code == CodeCapacity {
			next = active.position
		}
		var err error
		active, err = c.establish(runCtx, next, true, result.err.Code)
		if err != nil {
			return err
		}
	}
}

func (c *Client) forwardGeneration(ctx context.Context, device tunnel.PacketConn, active *connection, configure TunnelConfigurer, inbound, outbound []byte) forwardingError {
	if configure == nil {
		return c.forwardSession(ctx, device, active, inbound, outbound)
	}
	info, ok := controlInfo(active)
	if !ok {
		return forwardingError{err: &Error{Op: "configure tunnel", Code: CodeTunnel}}
	}
	generationCtx, cancel := context.WithCancel(ctx)
	var watcher sync.WaitGroup
	if status, ok := active.link.(sessionStatus); ok {
		watcher.Go(func() {
			select {
			case <-status.Done():
				cancel()
			case <-generationCtx.Done():
			}
		})
	}
	var rollback func()
	defer func() {
		cancel()
		watcher.Wait()
		if rollback != nil {
			rollback()
		}
	}()
	generation := TunnelGeneration{
		Number: active.generation, Endpoint: c.config.Endpoints[active.index], Control: info,
	}
	var err error
	if generationCtx.Err() == nil {
		rollback, err = configure(generationCtx, generation)
	}
	if outcome, ok := errors.AsType[interface {
		error
		TunnelCleanupFailed() bool
	}](err); ok && outcome.TunnelCleanupFailed() {
		return forwardingError{err: &Error{Op: "configure tunnel", Code: CodeTunnel}, tunnelCleanupFailed: true}
	}
	if err != nil && !errors.Is(err, generationCtx.Err()) {
		return forwardingError{err: &Error{Op: "configure tunnel", Code: CodeTunnel}}
	}
	if generationCtx.Err() != nil {
		return forwardingError{err: &Error{Op: "configure tunnel", Code: CodeNetwork}, fromSession: true}
	}
	// Loss cancels the configurator and its DNS sockets immediately.
	// Packet forwarding observes the session's own error so a canceled
	// device read cannot hide a reconnectable transport loss.
	return c.forwardSession(ctx, device, active, inbound, outbound)
}

func (c *Client) endSession(ctx context.Context, active *connection, result forwardingError) (forwardingError, error) {
	c.mu.Lock()
	ownsSession := c.active == active
	if ownsSession {
		c.active, c.closing = nil, active
	}
	c.mu.Unlock()

	var cleanupFailed bool
	if ownsSession {
		cleanupFailed = failedCleanup(active.link.Close())
		// A session can cancel I/O to release a blocked writer before the
		// writer sees the typed shutdown cause. Close joins session cleanup.
		if link, ok := active.link.(sessionStatus); ok && result.fromSession {
			if cause := link.Err(); cause != nil {
				code := packetErrorCode(cause, CodeNetwork)
				if code != CodeCanceled && (!canRecover(code) || canRecover(result.err.Code) || result.err.Code == CodeCanceled) {
					result.err = &Error{Op: "session", Code: code}
					result.sameEndpoint = errors.Is(cause, tlscontrol.ErrPeerRestartSame)
				}
			}
		}
		if cleanupFailed && result.err != nil && canRecover(result.err.Code) {
			result.err = &Error{Op: "close session", Code: CodeCleanup}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	stopped := c.operationError(ctx, "run")
	if result.tunnelCleanupFailed {
		active.cleanupFailed, c.cleanupFailed = true, true
	}
	if ownsSession {
		active.cleanupFailed = active.cleanupFailed || cleanupFailed
		c.cleanupFailed = c.cleanupFailed || cleanupFailed
		var code ErrorCode
		if stopped == nil {
			c.state = StateIdle
			code = result.err.Code
		}
		c.disconnected(active, code)
	}
	return result, stopped
}

type forwardingError struct {
	err                 *Error
	fromSession         bool
	sameEndpoint        bool
	tunnelCleanupFailed bool
}

func (c *Client) forwardSession(ctx context.Context, device tunnel.PacketConn, active *connection, inbound, outbound []byte) forwardingError {
	ctx, cancel := context.WithCancel(ctx)
	results := make(chan forwardingError, 2)
	var workers sync.WaitGroup
	workers.Go(func() {
		results <- forward(ctx, device, active.link, inbound, true, &c.recv, &active.recv, &c.packetDrops)
	})
	workers.Go(func() {
		results <- forward(ctx, active.link, device, outbound, false, &c.sent, &active.sent, &c.packetDrops)
	})
	result := <-results
	cancel()
	workers.Wait()
	other := <-results
	if result.fromSession && other.fromSession && other.err.Code != CodeCanceled &&
		(canRecover(result.err.Code) || result.err.Code == CodeCanceled) && !canRecover(other.err.Code) {
		return other
	}
	return result
}

func forward(ctx context.Context, dst, src tunnel.PacketConn, packet []byte, readsSession bool, total, generation *observability.Traffic, localDrops *atomic.Uint64) forwardingError {
	defer clear(packet)
	for ctx.Err() == nil {
		n, err := src.ReadPacket(ctx, packet)
		if err != nil {
			if !readsSession && errors.Is(err, io.ErrShortBuffer) {
				localDrops.Add(1)
				continue
			}
			return forwardError("read packet", err, readsSession)
		}
		if n <= 0 || n > len(packet) {
			return forwardError("read packet", data.ErrPacket, readsSession)
		}
		if err := ctx.Err(); err != nil {
			return forwardError("forward", err, readsSession)
		}
		if err := dst.WritePacket(ctx, packet[:n]); err != nil {
			if tunnel.IsMTUExceeded(err) || !readsSession && errors.Is(err, tunnel.ErrInvalidPacket) {
				localDrops.Add(1)
				continue
			}
			return forwardError("write packet", err, !readsSession)
		}
		total.Add(n)
		generation.Add(n)
	}
	return forwardError("forward", ctx.Err(), readsSession)
}

func failedCleanup(err error) bool {
	return err != nil && !errors.Is(err, net.ErrClosed)
}

func forwardError(op string, err error, fromSession bool) forwardingError {
	code := contextCode(err, CodeTunnel)
	if fromSession {
		code = packetErrorCode(err, CodeNetwork)
	}
	return forwardingError{
		err: &Error{Op: op, Code: code}, fromSession: fromSession,
		sameEndpoint: fromSession && errors.Is(err, tlscontrol.ErrPeerRestartSame),
	}
}

func packetErrorCode(err error, fallback ErrorCode) ErrorCode {
	if failure, ok := errors.AsType[*Error](err); ok && failure.Code == CodeCapacity {
		return CodeCapacity
	}
	switch {
	case errors.Is(err, tlscontrol.ErrAuth):
		return CodeAuthentication
	case errors.Is(err, tlscontrol.ErrCertificate):
		return CodeCertificate
	case errors.Is(err, tlscontrol.ErrPeerRestart), errors.Is(err, tlscontrol.ErrPeerRestartSame):
		return CodePeerRestart
	case errors.Is(err, tlscontrol.ErrPeerStopped):
		return CodePeerStopped
	case errors.Is(err, control.ErrProtection):
		return CodeConfig
	case errors.Is(err, data.ErrKeyLimit), errors.Is(err, data.ErrPacket), errors.Is(err, crypt.ErrDataKeys),
		errors.Is(err, tlscontrol.ErrNegotiation):
		return CodeProtocol
	}
	if code := contextCode(err, ""); code != "" {
		return code
	}
	switch {
	case errors.Is(err, control.ErrTransport), errors.Is(err, control.ErrRetransmit),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.ErrClosedPipe),
		errors.Is(err, net.ErrClosed):
		return CodeNetwork
	case errors.Is(err, session.ErrRekey), errors.Is(err, control.ErrReliable),
		errors.Is(err, transport.ErrPacketTooLarge), errors.Is(err, transport.ErrEmptyPacket), errors.Is(err, io.ErrShortBuffer):
		return CodeProtocol
	default:
		return fallback
	}
}
