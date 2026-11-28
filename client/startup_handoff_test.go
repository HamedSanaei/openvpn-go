package client

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

type handoffTestLink struct {
	metadataLink
	cause, cleanup error
}

func (l handoffTestLink) Err() error          { return l.cause }
func (l handoffTestLink) CleanupError() error { return l.cleanup }

func TestManagedStartupRecoversAnEndedGeneration(t *testing.T) {
	for _, tc := range []struct {
		name              string
		cause, cleanup    error
		observe, disabled bool
		want              ErrorCode
		next              int
	}{
		{"recover", net.ErrClosed, nil, false, false, CodeCanceled, 1},
		{"observed", net.ErrClosed, nil, true, false, CodeCanceled, 1},
		{"restart same", tlscontrol.ErrPeerRestartSame, nil, true, false, CodeCanceled, 0},
		{"halt", tlscontrol.ErrPeerStopped, nil, true, false, CodePeerStopped, -1},
		{"auth", tlscontrol.ErrAuth, nil, false, false, CodeAuthentication, -1},
		{"protocol", tlscontrol.ErrNegotiation, nil, false, false, CodeProtocol, -1},
		{"cleanup", net.ErrClosed, errors.New("private cleanup detail"), true, false, CodeCleanup, -1},
		{"disabled", net.ErrClosed, nil, true, true, CodeNetwork, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ended := make(chan struct{})
				var visits []string
				var oldTransport transport.PacketConn
				c := retryClient(t, fallbackEndpoints[:2], RetryPolicy{InitialBackoff: time.Millisecond, DisableReconnect: tc.disabled},
					testkit.DialerFunc(func(_ context.Context, _ string, addr string) (transport.PacketConn, error) {
						visits = append(visits, addr)
						local, other := testkit.PacketPipe(1, 64)
						t.Cleanup(func() { other.Close() })
						return local, nil
					}))
				for index := range c.handshakes {
					c.handshakes[index] = func(_ context.Context, _ Endpoint, raw transport.PacketConn) (tunnel.PacketConn, error) {
						if len(visits) == 1 {
							oldTransport = raw
							return handoffTestLink{metadataLink: metadataLink{PacketConn: raw, done: ended}, cause: tc.cause, cleanup: tc.cleanup}, nil
						}
						return metadataLink{PacketConn: raw, done: make(chan struct{})}, nil
					}
				}
				dev, app := testkit.PacketPipe(1, 64)
				defer dev.Close()
				defer app.Close()
				assertCode(t, c.Run(t.Context(), dev), CodeNotConnected)
				if err := c.Connect(t.Context()); err != nil {
					t.Fatal(err)
				}
				oldTransport.Close()
				close(ended)
				if tc.observe {
					if c.State() != StateIdle || c.Stats().Disconnects != 1 {
						t.Fatal("observation did not finish the ended generation")
					}
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				configured := 0
				err := c.RunConfigured(ctx, dev, func(_ context.Context, gen TunnelGeneration) (func(), error) {
					configured++
					if gen.Number != 2 || tc.next < 0 || gen.Endpoint != fallbackEndpoints[tc.next] {
						t.Fatalf("configured unexpected generation %v", gen)
					}
					cancel()
					return nil, nil
				})
				assertCode(t, err, tc.want)
				want := []string{fallbackEndpoints[0].address()}
				wantConfigured := 0
				if tc.next >= 0 {
					want = append(want, fallbackEndpoints[tc.next].address())
					wantConfigured = 1
				}
				reports := c.CompletedGenerationReports(0)
				if !slices.Equal(visits, want) || configured != wantConfigured ||
					len(reports) != 1+wantConfigured || reports[0].CleanupFailed != (tc.cleanup != nil) {
					t.Fatalf("visits %v, configured %d, reports %v", visits, configured, reports)
				}
			})
		})
	}
}
