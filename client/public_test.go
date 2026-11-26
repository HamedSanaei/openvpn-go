package client_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

func TestPublicClientRequiresTLSBeforeDialing(t *testing.T) {
	c, err := client.New(client.Config{
		Endpoints: []client.Endpoint{{Host: "vpn.example.test"}},
		Dialer: testkit.DialerFunc(func(ctx context.Context, network, address string) (transport.PacketConn, error) {
			t.Errorf("unexpected dial to %s %s", network, address)
			return nil, net.ErrClosed
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	var failure *client.Error
	err = c.Connect(t.Context())
	if !errors.As(err, &failure) || failure.Code != client.CodeConfig || failure.Field != "TLS" {
		t.Fatalf("Connect = %v; want missing TLS configuration", err)
	}
	if c.State() != client.StateIdle {
		t.Fatalf("state = %s", c.State())
	}
}
