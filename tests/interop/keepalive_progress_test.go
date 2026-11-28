//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
	"github.com/hamedsanaei/openvpn-go/transport"
)

type blockFirstKeepalive struct {
	transport.PacketConn
	blocked, release chan struct{}
	writes           atomic.Int32
}

func (p *blockFirstKeepalive) WritePacket(ctx context.Context, packet []byte) error {
	if len(packet) == data.Overhead+len(data.Keepalive) && wire.Opcode(packet[0]>>3) == wire.DataV2 &&
		p.writes.Add(1) == 1 {
		close(p.blocked)
		select {
		case <-p.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return p.PacketConn.WritePacket(ctx, packet)
}

func TestBlockedKeepaliveAllowsReceiveAndRekeyAdmission(t *testing.T) {
	pki := testkit.NewPKI(t)
	f := makePKIFixture(t, interopPeer(t), pki)
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			port, echo := startDataPeer(t, f, network, "tls", false, "1.3", "AES-256-GCM",
				"--keepalive", "1", "20", "--reneg-sec", "0")
			limiter, err := client.NewHandshakeLimiter(1, 1)
			if err != nil {
				t.Fatal(err)
			}
			cfg := f.config(pki, network, "tls", port, false)
			cfg.RekeyInterval, cfg.HandshakeLimiter = 3*time.Second, limiter
			conn := &blockFirstKeepalive{blocked: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(conn.release) })
			defer release()
			cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, network, address string) (transport.PacketConn, error) {
				raw, err := (transport.SocketDialer{}).DialPacket(ctx, network, address)
				if err != nil {
					return nil, err
				}
				conn.PacketConn = raw
				return conn, nil
			})
			c, app := connectData(t, cfg)
			info, ok := c.ControlInfo()
			if !ok || !info.TunnelIP.Is4() {
				t.Fatal("expected a verified IPv4 tunnel")
			}
			blockerCfg := f.config(pki, network, "tls", port, false)
			blockerCfg.HandshakeLimiter = limiter
			holding := make(chan struct{})
			blockerCfg.Dialer = testkit.DialerFunc(func(ctx context.Context, _, _ string) (transport.PacketConn, error) {
				close(holding)
				<-ctx.Done()
				return nil, ctx.Err()
			})
			blocker, err := client.New(blockerCfg)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Close()
			blockCtx, unblock := context.WithCancel(t.Context())
			defer unblock()
			go blocker.Connect(blockCtx)
			select {
			case <-holding:
			case <-time.After(time.Second):
				t.Fatal("handshake slot not held")
			}
			select {
			case <-conn.blocked:
			case <-time.After(2500 * time.Millisecond):
				t.Fatal("first keepalive did not reach the controlled socket")
			}
			message := []byte("verified inbound while keepalive is waiting")
			if _, err := echo.WriteToUDPAddrPort(message, netip.AddrPortFrom(info.TunnelIP, 26022)); err != nil {
				t.Fatal(err)
			}
			var buf [1500]byte
			readCtx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			n, err := app.ReadPacket(readCtx, buf[:])
			if err != nil || n != len(message)+28 || !bytes.Equal(buf[28:n], message) {
				t.Fatalf("inbound forwarding during keepalive write: n=%d, %v", n, err)
			}
			awaitAdmissionCondition(t, 3*time.Second, func() bool { return limiter.Stats().Waiting == 1 })
			if n := conn.writes.Load(); n != 1 {
				t.Fatalf("keepalive was not coalesced: %d writes", n)
			}
			unblock()
			release()
			waitForKeyID(t, c, 1)
			roundtrip(t, app, echo, info.TunnelIP.AsSlice(), []byte("forwarding after keepalive and rekey"))
		})
	}
}
