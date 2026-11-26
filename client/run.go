package client

import (
	"context"
	"errors"
	"sync"

	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/session"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

// Run forwards complete IP packets between the authenticated session and
// device. It borrows device, which remains open on return. One Run may be
// active at a time. Cancel the context or call Close to stop forwarding.
// When forwarding ends, Run releases the session and a new Connect is needed.
func (c *Client) Run(ctx context.Context, device tunnel.PacketConn) error {
	if device == nil {
		return configError("tunnel")
	}
	c.mu.Lock()
	c.observeSession()
	switch {
	case c.state == StateClosing || c.state == StateClosed:
		c.mu.Unlock()
		return &Error{Op: "run", Code: CodeClosed}
	case c.state != StateConnected:
		c.mu.Unlock()
		return &Error{Op: "run", Code: CodeNotConnected}
	case c.run != nil:
		c.mu.Unlock()
		return &Error{Op: "run", Code: CodeBusy}
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return &Error{Op: "run", Code: contextCode(err, CodeTunnel)}
	}

	runCtx, cancel := context.WithCancel(ctx)
	run := &operation{cancel: cancel, done: make(chan struct{})}
	c.run = run
	session := c.session
	c.mu.Unlock()

	results := make(chan error, 2)
	limit := c.config.MaxPacketSize
	var workers sync.WaitGroup
	workers.Go(func() {
		results <- forward(runCtx, device, session, limit, CodeNetwork, CodeTunnel)
	})
	workers.Go(func() {
		results <- forward(runCtx, session, device, limit, CodeTunnel, CodeNetwork)
	})
	err := <-results
	cancel()
	workers.Wait()

	c.mu.Lock()
	ownsSession := c.state == StateConnected
	if ownsSession {
		c.session = nil
		c.state = StateIdle
	}
	c.mu.Unlock()

	// Close takes ownership if it has already started closing the client.
	if ownsSession {
		session.Close()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.run = nil
	close(run.done)
	if c.state == StateClosing {
		return &Error{Op: "run", Code: CodeClosed}
	}
	if ctx.Err() != nil {
		return &Error{Op: "run", Code: contextCode(ctx.Err(), CodeTunnel)}
	}
	return err
}

func forward(ctx context.Context, dst, src tunnel.PacketConn, limit int, readCode, writeCode ErrorCode) error {
	packet := make([]byte, limit)
	for ctx.Err() == nil {
		n, err := src.ReadPacket(ctx, packet)
		if err != nil {
			return &Error{Op: "read packet", Code: packetErrorCode(err, readCode)}
		}
		if n <= 0 || n > len(packet) {
			return &Error{Op: "read packet", Code: readCode}
		}
		if err := dst.WritePacket(ctx, packet[:n]); err != nil {
			return &Error{Op: "write packet", Code: packetErrorCode(err, writeCode)}
		}
	}
	return &Error{Op: "forward", Code: contextCode(ctx.Err(), readCode)}
}

func packetErrorCode(err error, fallback ErrorCode) ErrorCode {
	switch {
	case errors.Is(err, tlscontrol.ErrAuth):
		return CodeAuthentication
	case errors.Is(err, tlscontrol.ErrCertificate):
		return CodeCertificate
	case errors.Is(err, session.ErrRekey), errors.Is(err, data.ErrKeyLimit), errors.Is(err, data.ErrPacket):
		return CodeProtocol
	default:
		return contextCode(err, fallback)
	}
}
