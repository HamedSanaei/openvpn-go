package client

import (
	"context"
	"errors"
	"sync"

	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

// ClientState is a snapshot of the client lifecycle.
type ClientState uint8

const (
	StateIdle ClientState = iota
	StateDialing
	StateHandshaking
	StateConnected
	StateClosing
	StateClosed
)

func (s ClientState) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateDialing:
		return "dialing"
	case StateHandshaking:
		return "handshaking"
	case StateConnected:
		return "connected"
	case StateClosing:
		return "closing"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

type operation struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// A handshake returns an authenticated IP packet session. A returned session
// takes ownership of the transport. Connect closes the transport directly if
// no session is returned.
type handshakeFunc func(context.Context, Endpoint, transport.PacketConn) (tunnel.PacketConn, error)

// Client owns the authenticated session and coordinates its lifecycle.
// Construct a Client with New and use it through a pointer.
type Client struct {
	config    Config
	handshake handshakeFunc

	mu      sync.Mutex
	state   ClientState
	attempt *operation
	run     *operation
	session tunnel.PacketConn

	closeOnce sync.Once
	closeErr  error
}

// New validates the configuration without performing network I/O.
func New(config Config) (*Client, error) {
	cfg, err := config.validated()
	if err != nil {
		return nil, err
	}
	handshake, err := prepareHandshake(cfg)
	if err != nil {
		return nil, err
	}
	cfg.TLS, cfg.Credentials, cfg.Control.Key, cfg.DataCiphers = nil, nil, nil, nil
	return &Client{config: cfg, handshake: handshake}, nil
}

// State returns a concurrent-safe lifecycle snapshot.
func (c *Client) State() ClientState {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observeSession()
	return c.state
}

// ActiveEndpoint reports the remote of an authenticated session, if one exists.
func (c *Client) ActiveEndpoint() (Endpoint, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.observeSession()
	if c.state != StateConnected {
		return Endpoint{}, false
	}
	return c.config.Endpoints[0], true
}

// Connect starts one bounded connection attempt. It returns success only after
// TLS has authenticated the peer and data-channel keys are ready. The caller's context bounds the attempt. The authenticated control
// session outlives that context until it disconnects or Close is called.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	c.observeSession()
	switch c.state {
	case StateClosing, StateClosed:
		c.mu.Unlock()
		return &Error{Op: "connect", Code: CodeClosed}
	case StateDialing, StateHandshaking, StateConnected:
		c.mu.Unlock()
		return &Error{Op: "connect", Code: CodeBusy}
	}
	if c.run != nil {
		c.mu.Unlock()
		return &Error{Op: "connect", Code: CodeBusy}
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return &Error{Op: "connect", Code: contextCode(err, CodeNetwork)}
	}
	if c.handshake == nil {
		c.mu.Unlock()
		return configError("TLS")
	}
	ctx, cancel := context.WithCancel(ctx)
	attempt := &operation{cancel: cancel, done: make(chan struct{})}
	c.attempt = attempt
	c.state = StateDialing
	c.mu.Unlock()
	defer c.finishAttempt(attempt)

	session, err := c.connect(ctx, c.config.Endpoints[0])
	c.mu.Lock()
	if c.state == StateClosing {
		err = &Error{Op: "connect", Code: CodeClosed}
	} else if ctx.Err() != nil {
		err = &Error{Op: "connect", Code: contextCode(ctx.Err(), CodeNetwork)}
	}
	if err == nil {
		c.session = session
		c.state = StateConnected
	}
	c.mu.Unlock()

	if err != nil && session != nil {
		session.Close()
	}
	return err
}

func (c *Client) finishAttempt(attempt *operation) {
	attempt.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempt = nil
	if c.state == StateDialing || c.state == StateHandshaking {
		c.state = StateIdle
	}
	close(attempt.done)
}

func (c *Client) connect(ctx context.Context, endpoint Endpoint) (tunnel.PacketConn, error) {
	dialCtx, cancelDial := context.WithTimeout(ctx, c.config.ConnectTimeout)
	conn, err := c.config.Dialer.DialPacket(dialCtx, endpoint.Network, endpoint.address())
	if dialCtx.Err() != nil {
		err = dialCtx.Err()
	}
	cancelDial()
	if err != nil || conn == nil {
		if conn != nil {
			conn.Close()
		}
		return nil, &Error{Op: "dial", Code: contextCode(err, CodeNetwork)}
	}

	c.mu.Lock()
	if c.state == StateClosing || ctx.Err() != nil {
		c.mu.Unlock()
		conn.Close()
		return nil, &Error{Op: "handshake", Code: contextCode(ctx.Err(), CodeClosed)}
	}
	c.state = StateHandshaking
	c.mu.Unlock()

	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, c.config.HandshakeTimeout)
	session, err := c.handshake(handshakeCtx, endpoint, conn)
	if handshakeCtx.Err() != nil {
		err = handshakeCtx.Err()
	}
	cancelHandshake()
	if err != nil || session == nil {
		if session != nil {
			session.Close()
		} else {
			conn.Close()
		}
		code := contextCode(err, CodeProtocol)
		var handshakeError *Error
		if errors.As(err, &handshakeError) {
			code = handshakeError.Code
		}
		return nil, &Error{Op: "handshake", Code: code}
	}
	return session, nil
}

// Close permanently closes the client. It cancels in-flight operations, closes
// the owned session and waits for forwarding workers and connection setup to
// return. Concurrent calls return the same result.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.state = StateClosing
		attempt, run, session := c.attempt, c.run, c.session
		c.session = nil
		c.mu.Unlock()

		if attempt != nil {
			attempt.cancel()
		}
		if run != nil {
			run.cancel()
		}
		if session != nil {
			if err := session.Close(); err != nil {
				c.closeErr = &Error{Op: "close", Code: CodeNetwork}
			}
		}
		if attempt != nil {
			<-attempt.done
		}
		if run != nil {
			<-run.done
		}

		c.mu.Lock()
		c.state = StateClosed
		c.mu.Unlock()
	})
	return c.closeErr
}
