package client

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/failover"
	"github.com/hamedsanaei/openvpn-go/internal/observability"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
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
	cleanupFailed   bool
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

	mu            sync.Mutex
	state         ClientState
	attempt       *operation
	run           *operation
	active        *connection
	closing       *connection // retained until final counters are committed
	cleanupFailed bool

	stats       Stats
	events      observability.History[Event]
	attempts    *observability.History[AttemptReport]
	generations *observability.History[GenerationReport]
	rekeys      *observability.History[RekeyReport]
	sent        observability.Traffic
	recv        observability.Traffic
	packetDrops atomic.Uint64

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
	if c.cleanupFailed {
		c.mu.Unlock()
		return &Error{Op: "connect", Code: CodeCleanup}
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

func (c *Client) dial(ctx context.Context, index int, cursor *candidateCursor) (tunnel.PacketConn, AttemptStage, error, bool) {
	endpoint := c.config.Endpoints[index]
	timeout := endpoint.ConnectTimeout
	if timeout == 0 {
		timeout = c.config.ConnectTimeout
	}
	if limiter := c.config.HandshakeLimiter; limiter != nil {
		observability.Enter(ctx, observability.PhaseAdmission)
		// Admission is bounded by the endpoint's normal dial budget and
		// cancellation. Start socket-specific timers after the permit.
		waitCtx, cancel := context.WithTimeout(ctx, timeout)
		release, err := limiter.acquire(waitCtx)
		cancel()
		if err != nil {
			return nil, StageDial, &Error{Op: "admit handshake", Code: errorCode(err)}, false
		}
		defer release()
		observability.Enter(ctx, observability.PhaseTransport)
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
	conn, network, err := c.connectSocket(dialCtx, endpoint, cursor)
	_, cleanupFailed := errors.AsType[attemptCleanupFailure](err)
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
			cleanupFailed = failedCleanup(conn.Close()) || cleanupFailed
		}
		if errors.Is(err, transport.ErrProxyTarget) {
			return nil, stage, rejectedEndpointError{&Error{Op: "dial", Code: CodeConfig}}, cleanupFailed
		}
		code := contextCode(err, CodeNetwork)
		if errors.Is(err, transport.ErrInvalidPacketLimit) || errors.Is(err, transport.ErrUnsupportedNetwork) ||
			errors.Is(err, transport.ErrInvalidConnection) {
			code = CodeConfig
		} else if errors.Is(err, transport.ErrPeerCertificate) {
			code = CodeCertificate
		} else if errors.Is(err, transport.ErrProxyAuthentication) {
			code = CodeAuthentication
		}
		return nil, stage, &Error{Op: "dial", Code: code}, cleanupFailed
	}

	c.mu.Lock()
	if err := c.operationError(ctx, "handshake"); err != nil {
		c.mu.Unlock()
		return nil, StageControl, err, failedCleanup(conn.Close())
	}
	c.state = StateHandshaking
	c.record(EventHandshaking, index, "", 0)
	c.mu.Unlock()

	if !pollDeadline.IsZero() {
		endpoint.ServerPollTimeout = time.Until(pollDeadline)
		if endpoint.ServerPollTimeout <= 0 {
			return nil, StageControl, &Error{Op: "handshake", Code: CodeTimeout}, failedCleanup(conn.Close())
		}
	}
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, c.config.HandshakeTimeout)
	handshakeCtx, pendingExtended := tlscontrol.WithPendingParent(handshakeCtx, ctx)
	endpoint.Network = network
	session, err := c.handshakes[index](handshakeCtx, endpoint, conn)
	if ctx.Err() != nil {
		err = ctx.Err()
	} else if !pendingExtended() && handshakeCtx.Err() != nil {
		err = handshakeCtx.Err()
	}
	cancelHandshake()
	if err != nil || session == nil {
		if session == nil {
			session = conn
		}
		cleanupFailed = failedCleanup(session.Close())
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
		failure := &Error{Op: "handshake", Code: code}
		if _, same := errors.AsType[restartSameError](err); same {
			return nil, stage, restartSameError{failure}, cleanupFailed
		}
		return nil, stage, failure, cleanupFailed
	}
	return session, StageControl, nil, false
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
		if active != nil {
			c.active, c.closing = nil, active
		}
		c.mu.Unlock()

		if attempt != nil {
			attempt.cancel()
		}
		if run != nil {
			run.cancel()
		}
		var cleanupFailed bool
		if active != nil {
			closeLink := active.link.Close
			if graceful, ok := active.link.(interface{ CloseGracefully() error }); ok {
				closeLink = graceful.CloseGracefully
			}
			cleanupFailed = failedCleanup(closeLink())
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
		if cleanupFailed || c.cleanupFailed {
			code = CodeCleanup
			c.closeErr = &Error{Op: "close", Code: code}
		}
		if active != nil {
			active.cleanupFailed = active.cleanupFailed || cleanupFailed
			c.finishGeneration(active, code)
		}
		c.record(EventClosed, -1, code, 0)
		c.mu.Unlock()
	})
	return c.closeErr
}
