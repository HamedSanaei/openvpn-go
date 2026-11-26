package client

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/failover"
	"github.com/hamedsanaei/openvpn-go/internal/observability"
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
	StateBackoff
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
	case StateBackoff:
		return "backoff"
	default:
		return "unknown"
	}
}

type operation struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type connection struct {
	link            tunnel.PacketConn
	index, position int
	generation      uint64
	started         time.Time
	sent, recv      observability.Traffic
}

// A handshake returns an authenticated IP packet session. A returned session
// takes ownership of the transport. Connect closes the transport directly if
// no session is returned.
type handshakeFunc func(context.Context, Endpoint, transport.PacketConn) (tunnel.PacketConn, error)

// Client owns the authenticated session and coordinates its lifecycle.
// Construct a Client with New and use it through a pointer.
type Client struct {
	config     Config
	handshakes []handshakeFunc
	order      []int

	mu      sync.Mutex
	state   ClientState
	attempt *operation
	run     *operation
	active  *connection

	stats       Stats
	events      observability.History[Event]
	attempts    *observability.History[AttemptReport]
	generations *observability.History[GenerationReport]
	sent        observability.Traffic
	recv        observability.Traffic

	closeOnce sync.Once
	closeErr  error
}

// New validates the configuration without performing network I/O.
func New(config Config) (*Client, error) {
	cfg, err := config.validated()
	if err != nil {
		return nil, err
	}
	handshakes, err := prepareHandshakes(cfg)
	if err != nil {
		return nil, err
	}
	var shuffle func(int, func(int, int))
	if cfg.RemoteRandom {
		shuffle = rand.Shuffle
	}
	order := failover.Order(len(cfg.Endpoints), shuffle)
	cfg.TLS, cfg.Credentials, cfg.Control.Key, cfg.DataCiphers = nil, nil, nil, nil
	cfg.Authentication = Authentication{}
	cfg.EndpointControls = nil
	return &Client{config: cfg, handshakes: handshakes, order: order}, nil
}

// State returns a concurrent-safe lifecycle snapshot.
func (c *Client) State() ClientState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stateSnapshot()
}

// ActiveEndpoint reports the remote of an authenticated session, if one exists.
func (c *Client) ActiveEndpoint() (Endpoint, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	active := c.liveConnection()
	if active == nil {
		return Endpoint{}, false
	}
	return c.config.Endpoints[active.index], true
}

// Connect starts an attempt sequence in candidate order. The context bounds
// dialing, TLS and retry delays. A successful authenticated session outlives
// that context until it disconnects, Run finishes or Close is called.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	active := c.liveConnection()
	if err := c.operationError(ctx, "connect"); err != nil {
		c.mu.Unlock()
		return err
	}
	if c.attempt != nil || c.run != nil || active != nil {
		c.mu.Unlock()
		return &Error{Op: "connect", Code: CodeBusy}
	}
	if len(c.handshakes) == 0 || c.handshakes[0] == nil {
		c.mu.Unlock()
		return configError("TLS")
	}
	ctx, cancel := context.WithCancel(ctx)
	attempt := &operation{cancel: cancel, done: make(chan struct{})}
	c.attempt = attempt
	c.mu.Unlock()
	defer c.finish(attempt, &c.attempt)

	_, err := c.establish(ctx, 0, false, "")
	return err
}

func (c *Client) finish(op *operation, slot **operation) {
	op.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	*slot = nil
	if c.active == nil && c.state != StateClosing && c.state != StateClosed {
		c.state = StateIdle
	}
	close(op.done)
}

// operationError must be called with c.mu held.
func (c *Client) operationError(ctx context.Context, op string) error {
	if c.state == StateClosing || c.state == StateClosed {
		return &Error{Op: op, Code: CodeClosed}
	}
	if err := ctx.Err(); err != nil {
		return &Error{Op: op, Code: contextCode(err, CodeCanceled)}
	}
	return nil
}

func (c *Client) dial(ctx context.Context, index, visit int) (tunnel.PacketConn, AttemptStage, error) {
	endpoint := c.config.Endpoints[index]
	timeout := endpoint.ConnectTimeout
	if timeout == 0 {
		timeout = c.config.ConnectTimeout
	}
	var pollDeadline time.Time
	if endpoint.ServerPollTimeout != 0 {
		pollDeadline = time.Now().Add(endpoint.ServerPollTimeout)
	}
	dialDeadline := time.Now().Add(timeout)
	if !pollDeadline.IsZero() && pollDeadline.Before(dialDeadline) {
		dialDeadline = pollDeadline
	}
	dialCtx, cancelDial := context.WithDeadline(ctx, dialDeadline)
	conn, network, err := c.connectSocket(dialCtx, endpoint, visit)
	stage := StageDial
	if errors.Is(err, errResolution) {
		stage = StageResolve
	}
	if dialCtx.Err() != nil {
		err = dialCtx.Err()
	}
	if conn == nil && err == nil {
		err = transport.ErrInvalidConnection
	}
	cancelDial()
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		code := contextCode(err, CodeNetwork)
		if errors.Is(err, transport.ErrInvalidPacketLimit) || errors.Is(err, transport.ErrUnsupportedNetwork) ||
			errors.Is(err, transport.ErrInvalidConnection) {
			code = CodeConfig
		}
		return nil, stage, &Error{Op: "dial", Code: code}
	}

	c.mu.Lock()
	if err := c.operationError(ctx, "handshake"); err != nil {
		c.mu.Unlock()
		conn.Close()
		return nil, StageControl, err
	}
	c.state = StateHandshaking
	c.record(EventHandshaking, index, "", 0)
	c.mu.Unlock()

	if !pollDeadline.IsZero() {
		endpoint.ServerPollTimeout = time.Until(pollDeadline)
		if endpoint.ServerPollTimeout <= 0 {
			conn.Close()
			return nil, StageControl, &Error{Op: "handshake", Code: CodeTimeout}
		}
	}
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, c.config.HandshakeTimeout)
	endpoint.Network = network
	session, err := c.handshakes[index](handshakeCtx, endpoint, conn)
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
		stage = StageControl
		switch code {
		case CodeAuthentication:
			stage = StageAuthentication
		case CodeCertificate:
			stage = StageCertificate
		}
		return nil, stage, &Error{Op: "handshake", Code: code}
	}
	return session, StageControl, nil
}

// Close permanently closes the client. It cancels in-flight operations, closes
// the owned session and waits for forwarding workers and connection setup to
// return. Concurrent calls return the same result.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.liveConnection()
		c.state = StateClosing
		c.record(EventClosing, -1, "", 0)
		attempt, run, active := c.attempt, c.run, c.active
		c.active = nil
		c.mu.Unlock()

		if attempt != nil {
			attempt.cancel()
		}
		if run != nil {
			run.cancel()
		}
		if active != nil {
			closeLink := active.link.Close
			if graceful, ok := active.link.(interface{ CloseGracefully() error }); ok {
				closeLink = graceful.CloseGracefully
			}
			if err := closeLink(); err != nil {
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
		c.handshakes = nil
		c.config.Dialer = nil
		c.config.Resolver = nil
		c.state = StateClosed
		var code ErrorCode
		if c.closeErr != nil {
			code = CodeNetwork
		}
		if active != nil {
			c.finishGeneration(active, code)
		}
		c.record(EventClosed, -1, code, 0)
		c.mu.Unlock()
	})
	return c.closeErr
}
