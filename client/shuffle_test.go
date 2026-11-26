package client

import (
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/failover"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

func TestShuffledFailoverRetainsEveryEndpointAndItsHandshake(t *testing.T) {
	synctest.Test(t, testShuffledFailover)
}

func testShuffledFailover(t *testing.T) {
	original := []Endpoint{
		{Host: "one.example.test", Network: "udp4", Port: 1121},
		{Host: "two.example.test", Network: "tcp6", Port: 443},
		{Host: "three.example.test", Network: "tcp4", Port: 8443, ServerName: "name.example.test"},
		{Host: "four.example.test", Network: "udp6", Port: 1194},
	}
	shuffle := func() []int {
		return failover.Order(len(original), rand.New(rand.NewPCG(11, 47)).Shuffle)
	}
	first, second := shuffle(), shuffle()
	if slices.Equal([]int{0, 1, 2, 3}, first) || !slices.Equal(first, second) {
		t.Fatalf("unexpected seeded order: %+v and %+v", first, second)
	}
	var visited []int
	var raw []*countedConn
	cfg := Config{Endpoints: original, RemoteRandom: true, Retry: RetryPolicy{InitialBackoff: time.Millisecond}}
	cfg.Dialer = testkit.DialerFunc(func(_ context.Context, network, address string) (transport.PacketConn, error) {
		for i, endpoint := range original {
			if network == endpoint.Network && address == endpoint.address() {
				visited = append(visited, i)
				l, _ := testkit.PacketPipe(0, 64)
				conn := &countedConn{PacketConn: l}
				raw = append(raw, conn)
				return conn, nil
			}
		}
		return nil, errors.New("unexpected dial")
	})
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if sorted := slices.Sorted(slices.Values(c.order)); !slices.Equal(sorted, []int{0, 1, 2, 3}) {
		t.Fatalf("randomized constructor lost a candidate: %v", c.order)
	}
	c.order = first
	for i, endpoint := range c.config.Endpoints {
		c.handshakes[i] = func(_ context.Context, got Endpoint, raw transport.PacketConn) (tunnel.PacketConn, error) {
			if got != endpoint {
				t.Fatal("endpoint and handshake were separated")
			}
			if i == first[len(first)-1] {
				return raw, nil
			}
			return nil, &Error{Code: CodeNetwork}
		}
	}
	if err := c.Connect(t.Context()); err != nil {
		t.Fatal(err)
	}
	if active, ok := c.ActiveEndpoint(); !ok || active != c.config.Endpoints[first[len(first)-1]] || !slices.Equal(visited, first) {
		t.Fatalf("invalid selected candidate or visit order: %v", visited)
	}
	for _, conn := range raw[:len(raw)-1] {
		if conn.closes.Load() != 1 {
			t.Fatal("failed candidate transport did not close once")
		}
	}
}

func TestNewValidatesEveryEndpointControl(t *testing.T) {
	cfg := Config{Endpoints: []Endpoint{{Host: "one.example.test"}, {Host: "two.example.test"}}}
	for _, overrides := range [][]ControlProtection{
		{{Mode: ControlPlain}},
		{{Mode: ControlPlain}, {Mode: ControlTLSCrypt, Key: []byte("invalid")}},
	} {
		cfg.EndpointControls = overrides
		if _, err := New(cfg); err == nil {
			t.Fatal("accepted malformed endpoint controls")
		}
	}
}
