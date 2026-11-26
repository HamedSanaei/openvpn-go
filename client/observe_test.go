package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

func TestGenerationReportIsBoundedAndDetached(t *testing.T) {
	c := new(Client)
	for n := uint64(1); n <= 70; n++ {
		active := &connection{generation: n, index: 2, started: time.Now()}
		active.sent.Add(68)
		active.recv.Add(91)
		c.finishGeneration(active, CodeNetwork)
	}
	reports := c.GenerationReports(0)
	if len(reports) != 64 || reports[0].Generation != 7 || reports[63].Generation != 70 ||
		reports[63].PacketsSent != 1 || reports[63].BytesSent != 68 || reports[63].BytesReceived != 91 {
		t.Fatalf("unexpected generation history bounds or counters: %d", len(reports))
	}
	reports[63].EndedAt = time.Time{}
	if latest := c.GenerationReports(69); len(latest) != 1 || latest[0].EndedAt.IsZero() {
		t.Fatal("caller altered retained history")
	}
}

func TestRedactedAttemptReports(t *testing.T) {
	pki := testkit.NewPKI(t)
	cfg := Config{
		Endpoints:   []Endpoint{{Host: "private.example.test"}},
		Retry:       RetryPolicy{MaxAttempts: 2, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond},
		TLS:         &TLSConfig{CA: pki.CA, Certificate: pki.Client.Certificate, PrivateKey: pki.Client.PrivateKey},
		Credentials: &Credentials{Username: "hidden-user", Password: "hidden-password"},
	}
	started := make(chan struct{})
	dials := 0
	cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, _ string, _ string) (transport.PacketConn, error) {
		dials++
		if dials == 1 {
			return nil, errors.New("private address and cookie")
		}
		conn, _ := testkit.PacketPipe(1, 1024)
		return conn, nil
	})
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.handshakes[0] = func(ctx context.Context, _ Endpoint, _ transport.PacketConn) (tunnel.PacketConn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	complete := make(chan error, 1)
	go func() { complete <- c.Connect(ctx) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handshake did not start")
	}
	var wg sync.WaitGroup
	wg.Go(cancel)
	wg.Go(func() {
		for range 50 {
			c.AttemptReports(0)
			c.Events(0)
			c.GenerationReports(0)
		}
	})
	wg.Wait()
	if err := <-complete; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	reports := c.AttemptReports(0)
	if len(reports) != 2 || reports[0].Stage != StageDial || reports[0].Code != CodeNetwork ||
		reports[1].Stage != StageControl || reports[1].Code != CodeCanceled ||
		reports[1].RetryReason != CodeNetwork || reports[1].Sequence != reports[0].Sequence+1 ||
		reports[0].Started.After(reports[1].Started) || reports[1].RetryAfter <= 0 {
		t.Fatalf("unexpected attempt reports: %+v", reports)
	}
	raw, err := json.Marshal(reports)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"private.example.test", "hidden-user", "hidden-password", "cookie"} {
		if strings.Contains(string(raw), marker) {
			t.Fatal("attempt report serialized a secret")
		}
	}
}
