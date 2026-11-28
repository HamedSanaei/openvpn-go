package platform

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/integrations/sessions"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

type nativeTestDevice struct {
	tunnel.PacketConn
	closed *atomic.Int32
}

func (d nativeTestDevice) Close() error { d.closed.Add(1); return d.PacketConn.Close() }

type handoffDevice struct {
	tunnel.PacketConn
	closing chan struct{}
	resume  chan struct{}
	err     error
}

func (d handoffDevice) Close() error {
	close(d.closing)
	<-d.resume
	d.PacketConn.Close()
	return d.err
}

func TestHandoffPreservesTerminalLeaseJoinedDuringCleanup(t *testing.T) {
	for _, tc := range []struct {
		name        string
		factoryFail bool
		closeErr    error
		code        client.ErrorCode
	}{
		{"terminal_factory", true, nil, client.CodeTunnel},
		{"uncertain_cleanup", false, errors.New("private device failure"), client.CodeCanceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, err := sessions.New(sessions.Limits{Sessions: 1, PacketBytes: transport.DefaultPacketSize})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			changes := make(chan struct{})
			closing, resume, connected := make(chan struct{}), make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			defer release()
			var opens atomic.Int32
			pki := testkit.NewPKI(t)
			cfg := client.Config{
				Endpoints: []client.Endpoint{{Host: "127.0.0.1"}},
				TLS:       &client.TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey},
				Dialer: testkit.DialerFunc(func(ctx context.Context, _ string, _ string) (transport.PacketConn, error) {
					close(connected)
					<-ctx.Done()
					return nil, ctx.Err()
				}),
			}
			result := make(chan sessions.Status, 1)
			go func() {
				status, _ := Run(ctx, manager, "handoff", cfg, func(context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error) {
					if opens.Add(1) != 1 {
						return nil, nil, errors.New("unexpected readmission")
					}
					raw, _ := testkit.PacketPipe(1, 64)
					device := handoffDevice{raw, closing, resume, tc.closeErr}
					if tc.factoryFail {
						return device, nil, errors.New("terminal device initialization failure")
					}
					return device, nil, nil
				}, changes)
				result <- status
			}()
			barrier := closing
			if !tc.factoryFail {
				barrier = connected
			}
			select {
			case <-barrier:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			select {
			case changes <- struct{}{}:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			release()
			select {
			case status := <-result:
				if !status.Done || status.Code != tc.code || status.Cleanup.DeviceFailed != (tc.closeErr != nil) ||
					opens.Load() != 1 || manager.Usage() != (sessions.Usage{}) {
					t.Fatalf("handoff lost terminal lease: %+v, opens=%d", status, opens.Load())
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

func TestNetworkChangeJoinsPreviousLeaseAndCancellation(t *testing.T) {
	manager, err := sessions.New(sessions.Limits{Sessions: 1, PacketBytes: transport.DefaultPacketSize})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	use := make(chan struct{}, 2)
	changes := make(chan struct{}, 1)
	var opens, closed atomic.Int32
	pki := testkit.NewPKI(t)
	cfg := client.Config{Endpoints: []client.Endpoint{{Host: "127.0.0.1"}},
		TLS: &client.TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey},
		Dialer: testkit.DialerFunc(func(ctx context.Context, _ string, _ string) (transport.PacketConn, error) {
			use <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		})}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := Run(ctx, manager, "test-native", cfg, func(context.Context) (tunnel.PacketConn, client.TunnelConfigurer, error) {
			if before := opens.Add(1) - 1; closed.Load() != before {
				return nil, nil, errors.New("previous native tunnel still open")
			}
			dev, _ := testkit.PacketPipe(1, 1024)
			return nativeTestDevice{dev, &closed}, nil, nil
		}, changes)
		finished <- err
	}()
	await := func() {
		t.Helper()
		select {
		case <-use:
		case err := <-finished:
			t.Fatalf("early finish: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	await()
	changes <- struct{}{}
	await()
	close(changes)
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) || opens.Load() != 2 || closed.Load() != 2 {
		t.Fatalf("native revocation: %v, opens=%d closes=%d", err, opens.Load(), closed.Load())
	}
}
