package client

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

type attemptCleanupConn struct {
	transport.PacketConn
	closes atomic.Int32
	err    error
}

func (c *attemptCleanupConn) Close() error {
	c.closes.Add(1)
	c.PacketConn.Close()
	return c.err
}

func TestUnpublishedAttemptPreservesPrimaryAndCleanupFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     ErrorCode
		stage    AttemptStage
		closeErr error
	}{
		{"cancelled_session", CodeCanceled, StageControl, errors.New("private cleanup")},
		{"certificate", CodeCertificate, StageCertificate, errors.New("private cleanup")},
		{"authentication", CodeAuthentication, StageAuthentication, errors.New("private cleanup")},
		{"partial_transport", CodeNetwork, StageDial, errors.New("private cleanup")},
		{"already_closed", CodeCanceled, StageControl, net.ErrClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, peer := testkit.PacketPipe(1, 64)
			defer peer.Close()
			packet := &attemptCleanupConn{PacketConn: raw, err: tc.closeErr}
			var dials int
			c := retryClient(t, fallbackEndpoints[:2], RetryPolicy{MaxAttempts: 3},
				testkit.DialerFunc(func(_ context.Context, _, _ string) (transport.PacketConn, error) {
					dials++
					if dials > 1 {
						next, remote := testkit.PacketPipe(1, 64)
						t.Cleanup(func() { remote.Close() })
						return next, nil
					}
					if tc.stage == StageDial {
						return packet, errors.New("private dial error")
					}
					return packet, nil
				}))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			c.handshakes[0] = func(_ context.Context, _ Endpoint, link transport.PacketConn) (tunnel.PacketConn, error) {
				if tc.code == CodeCanceled {
					cancel()
					return link, nil
				}
				return nil, &Error{Op: "handshake", Code: tc.code}
			}
			err := c.Connect(ctx)
			assertCode(t, err, tc.code)
			if tc.code == CodeCanceled && !errors.Is(err, context.Canceled) {
				t.Fatal("lost the cancellation cause")
			}
			if strings.Contains(err.Error(), "private") || dials != 1 || packet.closes.Load() != 1 {
				t.Fatalf("attempt was retried, closed twice or exposed a raw error: %v", err)
			}
			uncertain := !errors.Is(tc.closeErr, net.ErrClosed)
			reports := c.AttemptReports(0)
			if len(reports) != 1 || reports[0].Code != tc.code || reports[0].Stage != tc.stage ||
				reports[0].CleanupFailed != uncertain || reports[0].Generation != 0 {
				t.Fatalf("unexpected attempt report: %+v", reports)
			}
			if uncertain {
				if !strings.Contains(err.Error(), string(CodeCleanup)) {
					t.Fatal("the returned error omitted the redacted cleanup failure")
				}
				assertCode(t, c.Connect(t.Context()), CodeCleanup)
				assertCode(t, c.Close(), CodeCleanup)
				if dials != 1 || packet.closes.Load() != 1 {
					t.Fatal("uncertain cleanup did not block new dials or preserve ownership")
				}
			} else {
				c.handshakes[0] = acceptTestSession
				if err := c.Connect(t.Context()); err != nil || dials != 2 {
					t.Fatalf("benign close blocked a new attempt: %v", err)
				}
			}
		})
	}
}

func TestCloseJoinsUnpublishedCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	raw, peer := testkit.PacketPipe(1, 64)
	defer peer.Close()
	packet := &attemptCleanupConn{PacketConn: raw, err: errors.New("private cleanup")}
	c := retryClient(t, fallbackEndpoints[:1], RetryPolicy{}, testkit.DialerFunc(
		func(context.Context, string, string) (transport.PacketConn, error) { return packet, nil }))
	entered := make(chan struct{})
	c.handshakes[0] = func(ctx context.Context, _ Endpoint, link transport.PacketConn) (tunnel.PacketConn, error) {
		close(entered)
		<-ctx.Done()
		return link, nil
	}
	attempt := make(chan error, 1)
	go func() { attempt <- c.Connect(ctx) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	assertCode(t, c.Close(), CodeCleanup)
	assertCode(t, <-attempt, CodeClosed)
	if packet.closes.Load() != 1 {
		t.Fatal("concurrent Close touched the unpublished connection twice")
	}
}
