package tlscontrol

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/control"
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
	TLS     *tls.Config
	Network string
	Digest  string
	Ciphers []string
	Auth    *Authentication
}

func Establish(ctx context.Context, stream *control.Stream, opts Options, previous *Negotiation) (*Link, error) {
	if err := stream.WaitReady(ctx); err != nil {
		return nil, err
	}
	conn := tls.Client(stream.Conn(), opts.TLS.Clone())
	if err := conn.HandshakeContext(ctx); err != nil {
		var verify *tls.CertificateVerificationError
		if errors.As(err, &verify) {
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
	if err := writeKeyMethod(conn, opts.Network, opts.Digest, opts.Ciphers, opts.Auth.credentials()); err != nil {
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
		push := pushState{allowed: opts.Ciphers}
		if err := readPush(ctx, conn, reader, &push); err != nil {
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

func readPush(ctx context.Context, conn net.Conn, reader *bufio.Reader, push *pushState) error {
	var commands commandReader
	defer func() { clear(commands.partial) }()
	for ctx.Err() == nil {
		if _, err := conn.Write([]byte("PUSH_REQUEST\x00")); err != nil {
			return err
		}
		next := time.Now().Add(pushRetry)
		if deadline, ok := ctx.Deadline(); ok && deadline.Before(next) {
			next = deadline
		}
		if err := conn.SetReadDeadline(next); err != nil {
			return err
		}

		for ctx.Err() == nil {
			message, err := commands.read(reader)
			if err != nil {
				var timeout net.Error
				if errors.As(err, &timeout) && timeout.Timeout() {
					break
				}
				return err
			}
			complete, err := push.add(message)
			clear(message)
			if err != nil || complete {
				return err
			}
		}
	}
	return ctx.Err()
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
