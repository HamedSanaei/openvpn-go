package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

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
		result := c.forwardSession(runCtx, device, active.link, inbound, outbound)
		result, stopped := c.endSession(runCtx, active, result)
		if stopped != nil {
			return stopped
		}
		if !result.fromSession || !canRetry(result.err.Code) || c.config.Retry.DisableReconnect {
			return result.err
		}
		next := (active.position + 1) % len(c.order)
		if result.sameEndpoint {
			next = active.position
		}
		var err error
		active, err = c.establish(runCtx, next, true, result.err.Code)
		if err != nil {
			return err
		}
	}
}

func (c *Client) endSession(ctx context.Context, active *connection, result forwardingError) (forwardingError, error) {
	c.mu.Lock()
	ownsSession := c.active == active
	if ownsSession {
		c.active = nil
	}
	c.mu.Unlock()

	if ownsSession {
		active.link.Close()
		// A session can cancel I/O to release a blocked writer before the
		// writer sees the typed shutdown cause. Close joins session cleanup.
		if link, ok := active.link.(sessionStatus); ok && result.fromSession {
			if cause := link.Err(); cause != nil {
				code := packetErrorCode(cause, CodeNetwork)
				if code != CodeCanceled && (!canRetry(code) || canRetry(result.err.Code) || result.err.Code == CodeCanceled) {
					result.err = &Error{Op: "session", Code: code}
					result.sameEndpoint = errors.Is(cause, tlscontrol.ErrPeerRestartSame)
				}
			}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	stopped := c.operationError(ctx, "run")
	if ownsSession {
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
	err          *Error
	fromSession  bool
	sameEndpoint bool
}

func (c *Client) forwardSession(ctx context.Context, device, link tunnel.PacketConn, inbound, outbound []byte) forwardingError {
	ctx, cancel := context.WithCancel(ctx)
	results := make(chan forwardingError, 2)
	var workers sync.WaitGroup
	workers.Go(func() {
		results <- forward(ctx, device, link, inbound, true, &c.recv)
	})
	workers.Go(func() {
		results <- forward(ctx, link, device, outbound, false, &c.sent)
	})
	result := <-results
	cancel()
	workers.Wait()
	other := <-results
	if result.fromSession && other.fromSession && other.err.Code != CodeCanceled &&
		(canRetry(result.err.Code) || result.err.Code == CodeCanceled) && !canRetry(other.err.Code) {
		return other
	}
	return result
}

func forward(ctx context.Context, dst, src tunnel.PacketConn, packet []byte, readsSession bool, traffic *observability.Traffic) forwardingError {
	defer clear(packet)
	for ctx.Err() == nil {
		n, err := src.ReadPacket(ctx, packet)
		if err != nil {
			return forwardError("read packet", err, readsSession)
		}
		if n <= 0 || n > len(packet) {
			return forwardError("read packet", data.ErrPacket, readsSession)
		}
		if err := ctx.Err(); err != nil {
			return forwardError("forward", err, readsSession)
		}
		if err := dst.WritePacket(ctx, packet[:n]); err != nil {
			return forwardError("write packet", err, !readsSession)
		}
		traffic.Add(n)
	}
	return forwardError("forward", ctx.Err(), readsSession)
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
	switch {
	case errors.Is(err, tlscontrol.ErrAuth):
		return CodeAuthentication
	case errors.Is(err, tlscontrol.ErrCertificate):
		return CodeCertificate
	case errors.Is(err, tlscontrol.ErrPeerRestart), errors.Is(err, tlscontrol.ErrPeerRestartSame):
		return CodePeerRestart
	case errors.Is(err, tlscontrol.ErrPeerStopped):
		return CodePeerStopped
	case errors.Is(err, control.ErrTransport), errors.Is(err, control.ErrRetransmit),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.ErrClosedPipe),
		errors.Is(err, net.ErrClosed):
		return CodeNetwork
	case errors.Is(err, context.DeadlineExceeded):
		return CodeTimeout
	case errors.Is(err, context.Canceled):
		return CodeCanceled
	case errors.Is(err, control.ErrProtection):
		return CodeConfig
	case errors.Is(err, session.ErrRekey), errors.Is(err, data.ErrKeyLimit), errors.Is(err, data.ErrPacket),
		errors.Is(err, control.ErrReliable), errors.Is(err, crypt.ErrDataKeys),
		errors.Is(err, transport.ErrPacketTooLarge), errors.Is(err, transport.ErrEmptyPacket), errors.Is(err, io.ErrShortBuffer),
		errors.Is(err, tlscontrol.ErrNegotiation):
		return CodeProtocol
	default:
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return CodeTimeout
		}
		return fallback
	}
}
