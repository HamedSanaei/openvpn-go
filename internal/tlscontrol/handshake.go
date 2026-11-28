package tlscontrol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/observability"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

const pushRetry = 3 * time.Second

// Link owns the authenticated TLS application stream over an established
// reliable control channel and provides its negotiated data keys.
type Link struct {
	Info        Negotiation
	stream      *control.Stream
	reader      *bufio.Reader
	conn        *tls.Conn
	auth        *Authentication
	classicKeys crypt.DataKeys
	authorityMu sync.Mutex
	retired     bool
	terminal    error
}

type Options struct {
	TLS               *tls.Config
	Network           string
	Digest            string
	Ciphers           []string
	Auth              *Authentication
	PushPolicy        tunnel.PushPolicy
	Interaction       Interaction
	ExitNotify        bool
	TunnelMTU         int
	FixedAEAD         string
	FixedDataV1       bool
	AllowLZOStub      bool
	AdvertiseDNS      bool
	ServerPollTimeout time.Duration
}

func Establish(ctx context.Context, stream *control.Stream, opts Options, previous *Negotiation) (_ *Link, failure error) {
	defer func() { failure = streamError(stream, failure) }()
	observability.Enter(ctx, observability.PhaseResetACK)
	pollCtx := ctx
	stopPoll := func() {}
	if previous == nil && opts.ServerPollTimeout != 0 {
		pollCtx, stopPoll = context.WithTimeout(ctx, opts.ServerPollTimeout)
	}
	err := stream.WaitReady(pollCtx)
	stopPoll()
	if err != nil {
		return nil, err
	}
	observability.Enter(ctx, observability.PhaseTLS)
	conn := tls.Client(stream.Conn(), opts.TLS.Clone())
	if err := conn.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var verify *tls.CertificateVerificationError
		if errors.As(err, &verify) || errors.Is(err, ErrCertificate) {
			return nil, ErrCertificate
		}
		return nil, err
	}
	// No control application bytes enter TLS until its peer is verified.
	activeCtx := ctx
	stopDeadline := func() {}
	defer func() {
		stopDeadline()
		conn.SetDeadline(time.Time{})
	}()
	setPhaseDeadline := func(phase context.Context) error {
		stopDeadline()
		activeCtx = phase
		deadline, _ := phase.Deadline()
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
		done := make(chan struct{})
		stop := context.AfterFunc(phase, func() {
			defer close(done)
			conn.SetDeadline(time.Now())
		})
		stopDeadline = func() {
			if !stop() {
				<-done
			}
		}
		return phase.Err()
	}
	if err := setPhaseDeadline(ctx); err != nil {
		return nil, err
	}

	reader := bufio.NewReaderSize(conn, 4096)
	var classic *crypt.ClassicMaterial
	if opts.FixedAEAD != "" {
		classic = new(crypt.ClassicMaterial)
		defer classic.Clear()
	}
	observability.Enter(ctx, observability.PhaseCredentials)
	user, err := opts.Auth.forHandshake(ctx, opts.Interaction.Credentials)
	if err != nil {
		return nil, err
	}
	observability.Enter(ctx, observability.PhaseKeyMethodWrite)
	if err := writeKeyMethodOptions(conn, opts.Network, opts.Digest, opts.Ciphers, user, opts, classic); err != nil {
		return nil, ctxError(ctx, err)
	}
	observability.Enter(ctx, observability.PhaseKeyMethodRead)
	if err := readPeerKeyMethodForFormat(ctx, reader, opts.FixedAEAD, classic, opts.FixedDataV1); err != nil {
		return nil, ctxError(ctx, err)
	}

	var info Negotiation
	if previous != nil {
		// The existing authenticated push governs soft-reset generations.
		observability.Enter(ctx, observability.PhaseRekeyDrain)
		if err := stream.Drain(ctx); err != nil {
			return nil, ctxError(ctx, err)
		}
		info = *previous
	} else {
		observability.Enter(ctx, observability.PhasePush)
		push := pushState{allowed: opts.Ciphers, policy: opts.PushPolicy, allowExit: opts.ExitNotify, fixedAEAD: opts.FixedAEAD, fixedDataV1: opts.FixedDataV1, allowLZOStub: opts.AllowLZOStub}
		pending := pendingAuth{Interaction: opts.Interaction}
		defer pending.close()
		if err := readPushWithPending(ctx, conn, reader, &push, &pending, setPhaseDeadline); err != nil {
			clear(push.token)
			return nil, ctxError(activeCtx, err)
		}
		if classic != nil {
			// The concise peer starts handling tunnel traffic only after
			// its PUSH_REPLY has been acknowledged on the control channel.
			if err := stream.Drain(activeCtx); err != nil {
				clear(push.token)
				return nil, ctxError(activeCtx, err)
			}
		}
		if err := activeCtx.Err(); err != nil {
			clear(push.token)
			return nil, err
		}
		if push.token != nil || push.tokenUser != "" {
			opts.Auth.set(push.token, push.tokenUser)
		}
		info = push.Negotiation
	}
	info.TLSVersion = conn.ConnectionState().Version
	link := &Link{Info: info, stream: stream, reader: reader, conn: conn, auth: opts.Auth}
	if classic != nil {
		observability.Enter(ctx, observability.PhaseKeyDerivation)
		local, peer := stream.KeyContext()
		link.classicKeys, err = crypt.ClassicDataKeys(info.Cipher, classic, local, peer)
		if err != nil {
			return nil, err
		}
	}
	return link, nil
}

func streamError(stream *control.Stream, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.ErrClosedPipe),
		errors.Is(err, io.ErrShortWrite), errors.Is(err, net.ErrClosed):
		if cause := stream.Err(); cause != nil {
			return cause
		}
		return control.ErrTransport
	case errors.Is(err, ErrCertificate), errors.Is(err, ErrAuth), errors.Is(err, ErrNegotiation),
		errors.Is(err, ErrPeerRestart), errors.Is(err, ErrPeerRestartSame), errors.Is(err, ErrPeerStopped),
		errors.Is(err, control.ErrTransport), errors.Is(err, control.ErrReliable),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return err
		}
		return ErrNegotiation
	}
}

func readPush(ctx context.Context, conn net.Conn, reader *bufio.Reader, push *pushState) error {
	return readPushInteractive(ctx, conn, reader, push, Interaction{})
}

func readPushInteractive(ctx context.Context, conn net.Conn, reader *bufio.Reader, push *pushState, interaction Interaction) error {
	pending := pendingAuth{Interaction: interaction}
	defer pending.close()
	return readPushWithPending(ctx, conn, reader, push, &pending, func(context.Context) error { return nil })
}

func readPushWithPending(ctx context.Context, conn net.Conn, reader *bufio.Reader, push *pushState,
	pending *pendingAuth, setPhaseDeadline func(context.Context) error) error {
	var commands commandReader
	defer func() { clear(commands.partial) }()
	current := ctx
	infoBudget := 16 << 10
	for current.Err() == nil {
		if deadline, ok := current.Deadline(); ok {
			if !time.Now().Before(deadline) {
				return context.DeadlineExceeded
			}
			if err := conn.SetWriteDeadline(deadline); err != nil {
				return err
			}
		}
		if err := current.Err(); err != nil {
			return err
		}
		if _, err := conn.Write([]byte("PUSH_REQUEST\x00")); err != nil {
			return ctxError(current, err)
		}
		next := time.Now().Add(pushRetry)
		if deadline, ok := current.Deadline(); ok && deadline.Before(next) {
			next = deadline
		}
		if err := conn.SetReadDeadline(next); err != nil {
			return err
		}

		for current.Err() == nil {
			message, err := commands.read(reader)
			if err != nil {
				var timeout net.Error
				if errors.As(err, &timeout) && timeout.Timeout() {
					break
				}
				return err
			}
			kind, _, _ := bytes.Cut(message, []byte{','})
			informational := bytes.Equal(kind, []byte("INFO")) || bytes.Equal(kind, []byte("ECHO"))
			if informational || bytes.Equal(kind, []byte("INFO_PRE")) {
				infoBudget -= len(message) + 1
				if infoBudget < 0 {
					clear(message)
					return ErrNegotiation
				}
				if informational {
					clear(message)
					continue
				}
			}
			handled, response, err := pending.handle(ctx, message)
			if handled {
				clear(message)
				if err != nil {
					return err
				}
				if current != pending.ctx {
					current = pending.ctx
					if err := setPhaseDeadline(current); err != nil {
						clear(response)
						return err
					}
					deadline, _ := current.Deadline()
					next = minTime(time.Now().Add(pushRetry), deadline)
					if err := conn.SetReadDeadline(next); err != nil {
						clear(response)
						return err
					}
				}
				if len(response) != 0 {
					deadline, _ := pending.ctx.Deadline()
					err = conn.SetWriteDeadline(deadline)
					if err == nil {
						err = pending.ctx.Err()
					}
					if err == nil {
						_, err = conn.Write(response)
					}
					clear(response)
					if err != nil {
						return ctxError(pending.ctx, err)
					}
				}
				continue
			}
			complete, err := push.add(message)
			clear(message)
			if err != nil || complete {
				return err
			}
		}
	}
	return current.Err()
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func ctxError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return fallback
}
