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
	"github.com/hamedsanaei/openvpn-go/transport"
)

func TestRetrySkipsOnlyRejectedProxyTargets(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			first := Endpoint{Host: "sensitive-invalid.example.test", Network: "tcp4"}
			other := Endpoint{Host: "sensitive-alternate.example.test", Network: "tcp"}
			endpoints := []Endpoint{first}
			if mixed {
				endpoints = append(endpoints, other)
			}
			var visits []string
			dialer := testkit.DialerFunc(func(_ context.Context, network, address string) (transport.PacketConn, error) {
				visits = append(visits, network)
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					t.Fatal(err)
				}
				if host == first.Host {
					return nil, errors.Join(transport.ErrProxyTarget, errors.New("private detail"))
				}
				if len(visits) < 4 {
					return nil, net.ErrClosed
				}
				local, peer := testkit.PacketPipe(1, 64)
				t.Cleanup(func() { peer.Close() })
				return local, nil
			})
			c := retryClient(t, endpoints, RetryPolicy{MaxAttempts: UnlimitedAttempts, InitialBackoff: time.Millisecond}, dialer)
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			err := c.Connect(ctx)
			attempts := c.AttemptReports(0)
			if !mixed {
				assertCode(t, err, CodeConfig)
				if !slices.Equal(visits, []string{"tcp4"}) || len(attempts) != 1 || attempts[0].Code != CodeConfig {
					t.Fatalf("deterministic target retried: visits %v, reports %v", visits, attempts)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(visits, []string{"tcp4", "tcp", "tcp", "tcp"}) || len(attempts) != 4 ||
				attempts[0].Code != CodeConfig || attempts[1].Code != CodeNetwork ||
				attempts[2].Code != CodeNetwork || attempts[3].Stage != StageConnected {
				t.Fatalf("unexpected visits %v or attempts %v", visits, attempts)
			}
		})
	}
}
