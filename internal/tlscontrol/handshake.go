package tlscontrol

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

const pushRetry = 3 * time.Second

// Link owns the authenticated TLS application stream over an established
// reliable control channel and provides its negotiated data keys.
type Link struct {
	Info   Negotiation
	stream *control.Stream
	reader *bufio.Reader
	conn   *tls.Conn
	auth   *Authentication
}

type Options struct {
	TLS         *tls.Config
	Network     string
	Digest      string
	Ciphers     []string
	Auth        *Authentication
	PushPolicy  tunnel.PushPolicy
	Interaction Interaction
	ExitNotify  bool
	TunnelMTU   int
}

func Establish(ctx context.Context, stream *control.Stream, opts Options, previous *Negotiation) (_ *Link, failure error) {
	defer func() { failure = streamError(stream, failure) }()
	if err := stream.WaitReady(ctx); err != nil {
		return nil, err
	}
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
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		conn.SetDeadline(time.Now())
	})
	defer func() {
		if !stop() {
			<-done
		}
		conn.SetDeadline(time.Time{})
	}()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	reader := bufio.NewReaderSize(conn, 4096)
	user, err := opts.Auth.forHandshake(ctx, opts.Interaction.Credentials)
	if err != nil {
		return nil, err
	}
	if err := writeKeyMethodOptions(conn, opts.Network, opts.Digest, opts.Ciphers, user, opts); err != nil {
		return nil, ctxError(ctx, err)
	}
	if err := readKeyMethod(reader); err != nil {
		return nil, ctxError(ctx, err)
	}

	var info Negotiation
	if previous != nil {
		// The existing authenticated push governs soft-reset generations.
		if err := stream.Drain(ctx); err != nil {
			return nil, ctxError(ctx, err)
		}
		info = *previous
	} else {
		push := pushState{allowed: opts.Ciphers, policy: opts.PushPolicy, allowExit: opts.ExitNotify}
		if err := readPushInteractive(ctx, conn, reader, &push, opts.Interaction); err != nil {
			clear(push.token)
			return nil, ctxError(ctx, err)
		}
		if push.token != nil {
			opts.Auth.set(push.token, push.tokenUser)
		}
		info = push.Negotiation
	}
	info.TLSVersion = conn.ConnectionState().Version
	return &Link{Info: info, stream: stream, reader: reader, conn: conn, auth: opts.Auth}, nil
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
	var commands commandReader
	defer func() { clear(commands.partial) }()
	pending := pendingAuth{Interaction: interaction}
	defer pending.close()
	current := ctx
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
			handled, response, err := pending.handle(ctx, message)
			if handled {
				clear(message)
				if err != nil {
					return err
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
				current = pending.ctx
				if deadline, _ := current.Deadline(); deadline.Before(next) {
					if err := conn.SetReadDeadline(deadline); err != nil {
						return err
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

func ctxError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return fallback
}
