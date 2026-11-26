package session

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

func TestAuthenticatedKeepaliveAndInvalidData(t *testing.T) {
	keys, err := crypt.ExportDataKeys(func(_ string, _ []byte, size int) ([]byte, error) {
		raw := make([]byte, size)
		for i := range raw {
			raw[i] = byte(i)
		}
		return raw, nil
	}, crypt.AES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	channel, err := data.NewChannel(0, true, keys)
	if err != nil {
		t.Fatal(err)
	}
	keys.Send, keys.Receive = keys.Receive, keys.Send
	peer, err := data.NewChannel(0, true, keys)
	if err != nil {
		t.Fatal(err)
	}
	s := &Session{
		channel: channel, inbound: make(chan []byte, 1), rotate: make(chan struct{}, 1),
		info:      tlscontrol.Negotiation{PingTimeout: time.Second},
		packetMTU: 1280, opts: Options{MaxPacketSize: 1400, TunnelMTU: 1280},
	}
	packet, err := peer.Seal([]byte(data.Keepalive))
	if err != nil {
		t.Fatal(err)
	}
	s.receive(packet)
	authenticated := s.lastRecv
	if authenticated.IsZero() || len(s.inbound) != 0 {
		t.Fatal("keepalive was forwarded or did not update authenticated liveness")
	}
	s.receive(packet)
	if !authenticated.Equal(s.lastRecv) {
		t.Fatal("a replay extended liveness")
	}

	packet, err = peer.Seal([]byte{42})
	if err != nil {
		t.Fatal(err)
	}
	s.receive(packet)
	if !authenticated.Equal(s.lastRecv) || len(s.inbound) != 0 {
		t.Fatal("non-IP data extended liveness or was forwarded")
	}
	if err := s.maintain(authenticated.Add(time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("liveness timeout = %v", err)
	}
	s.info.PingExit = true
	if err := s.maintain(authenticated.Add(time.Second)); !errors.Is(err, tlscontrol.ErrPeerStopped) {
		t.Fatalf("peer-requested exit = %v", err)
	}
	for _, size := range []int{1281, 1280} {
		cleartext := make([]byte, size)
		cleartext[0] = 0x60
		binary.BigEndian.PutUint16(cleartext[4:], uint16(size-40))
		if size > s.packetMTU && !errors.Is(s.WritePacket(t.Context(), cleartext), tunnel.ErrMTUExceeded) {
			t.Fatal("outbound packet above the inner MTU was accepted")
		}
		packet, err = peer.Seal(cleartext)
		if err != nil {
			t.Fatal(err)
		}
		s.receive(packet)
		if size > s.packetMTU {
			if len(s.inbound) != 0 || !s.lastRecv.Equal(authenticated) {
				t.Fatal("oversized authenticated packet was forwarded or refreshed liveness")
			}
		} else if len(s.inbound) != 1 || len(<-s.inbound) != size {
			t.Fatal("packet at the MTU was dropped")
		}
	}
	if err := s.WritePacket(t.Context(), make([]byte, 1400)); !errors.Is(err, tunnel.ErrMTUExceeded) {
		t.Fatalf("configured tunnel limit overrides outbound hard frame error: %v", err)
	}
	s.opts.TunnelMTU, s.packetMTU = 0, 1400-data.Overhead
	if err := s.WritePacket(t.Context(), make([]byte, 1400)); !errors.Is(err, transport.ErrPacketTooLarge) {
		t.Fatalf("hard frame limit = %v", err)
	}
}
