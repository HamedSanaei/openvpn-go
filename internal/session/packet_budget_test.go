package session

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

func TestUDPv4PacketBudgetPreventsOversizeSeal(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	raw, err := (transport.SocketDialer{MaxPacketSize: transport.MaxPacketSize}).
		DialPacket(ctx, "udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	opts := Options{MaxPacketSize: transport.MaxPacketSize}
	limit, mtu, fragments, err := packetBudget(raw, opts, true)
	if err != nil || limit != 65507 || mtu != 65507-data.Overhead || fragments != nil {
		t.Fatalf("IPv4 UDP budget: frame=%d mtu=%d fragments=%v: %v", limit, mtu, fragments, err)
	}
	mux, err := control.NewMux(raw, control.Protection{}, limit, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	keys, err := crypt.ExportDataKeys(func(_ string, _ []byte, size int) ([]byte, error) {
		return make([]byte, size), nil
	}, crypt.AES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	channel, err := data.NewChannel(0, true, keys)
	if err != nil {
		t.Fatal(err)
	}
	s := &Session{mux: mux, ctx: ctx, packetMTU: mtu, channel: channel, writeGate: make(chan struct{}, 1)}
	packet := func(size int) []byte {
		out := make([]byte, size)
		out[0] = 0x45
		binary.BigEndian.PutUint16(out[2:4], uint16(size))
		return out
	}
	if err := s.WritePacket(ctx, packet(mtu+1)); !errors.Is(err, tunnel.ErrMTUExceeded) {
		t.Fatalf("oversized packet: %v", err)
	}
	// Verify non-consumption of packet IDs even on systems whose UDP
	// socket ceiling is smaller than the protocol's absolute IP limit.
	check := func(t *testing.T, size int, id uint32, boundary bool) {
		t.Helper()
		if err := s.WritePacket(ctx, packet(size)); err != nil {
			if boundary && errors.Is(err, syscall.EMSGSIZE) {
				t.Skip("OS UDP socket limit below the absolute IPv4 payload ceiling")
			}
			t.Fatal(err)
		}
		_ = listener.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, transport.MaxPacketSize)
		n, _, err := listener.ReadFrom(buf)
		if err != nil || n != size+data.Overhead || binary.BigEndian.Uint32(buf[4:8]) != id {
			t.Fatalf("datagram bytes=%d id=%d: %v", n, binary.BigEndian.Uint32(buf[4:8]), err)
		}
	}
	check(t, 96, 1, false)
	t.Run("absolute-boundary", func(t *testing.T) {
		check(t, mtu, 2, true)
	})

	opts.FragmentSize = 65507
	limit, mtu, fragments, err = packetBudget(raw, opts, true)
	if err != nil || limit != 65507 || mtu != transport.MaxPacketSize ||
		fragments.chunkSize+fragmentHeaderSize+data.Overhead > limit {
		t.Fatalf("unexpected fragmented inner or outer limit: %d %d %v", limit, mtu, err)
	}
}

func TestPacketBudgetCustomDatagramFallback(t *testing.T) {
	conn, peer := testkit.PacketPipe(1, transport.MaxPacketSize)
	defer conn.Close()
	defer peer.Close()
	limit, mtu, _, err := packetBudget(conn, Options{MaxPacketSize: transport.MaxPacketSize}, true)
	if err != nil || limit != transport.MaxPacketSize || mtu != limit-data.Overhead {
		t.Fatalf("custom connection: frame=%d mtu=%d: %v", limit, mtu, err)
	}
}

func TestNativeIPv6DatagramAndTCPBudgets(t *testing.T) {
	for _, tc := range []struct {
		network, address string
		limit            int
	}{
		{"udp6", "[::1]:0", 65527},
		{"tcp4", "127.0.0.1:0", transport.MaxPacketSize},
	} {
		t.Run(tc.network, func(t *testing.T) {
			var endpoint net.Addr
			if tc.network == "udp6" {
				ln, err := net.ListenPacket(tc.network, tc.address)
				if err != nil {
					t.Skip("IPv6 loopback unavailable")
				}
				defer ln.Close()
				endpoint = ln.LocalAddr()
			} else {
				ln, err := net.Listen(tc.network, tc.address)
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				endpoint = ln.Addr()
			}
			wire, err := (transport.SocketDialer{MaxPacketSize: transport.MaxPacketSize}).
				DialPacket(t.Context(), tc.network, endpoint.String())
			if err != nil {
				t.Fatal(err)
			}
			defer wire.Close()
			limit, mtu, _, err := packetBudget(wire, Options{MaxPacketSize: transport.MaxPacketSize}, tc.network == "udp6")
			if err != nil || limit != tc.limit || mtu != tc.limit-data.Overhead {
				t.Fatalf("frame=%d mtu=%d: %v", limit, mtu, err)
			}
		})
	}
}
