package session

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/transport"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

func TestBlockIPv6DataPolicy(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	raw, err := (transport.SocketDialer{MaxPacketSize: 1500}).DialPacket(ctx, "udp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	mux, err := control.NewMux(raw, control.Protection{}, 1500, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	keys, err := crypt.ExportDataKeys(func(_ string, _ []byte, n int) ([]byte, error) {
		out := make([]byte, n)
		for i := range out {
			out[i] = byte(i)
		}
		return out, nil
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
	s := &Session{mux: mux, ctx: ctx, channel: channel, packetMTU: 1280, writeGate: make(chan struct{}, 1), inbound: make(chan []byte, 2), rotate: make(chan struct{}, 1), info: tlscontrol.Negotiation{Tunnel: tunnel.Configuration{BlockIPv6: true}}}
	v6 := make([]byte, 40)
	v6[0] = 0x60
	v4 := make([]byte, 20)
	v4[0] = 0x45
	binary.BigEndian.PutUint16(v4[2:4], uint16(len(v4)))
	if err := s.WritePacket(ctx, v6); !errors.Is(err, tunnel.ErrInvalidPacket) {
		t.Fatalf("blocked IPv6 write: %v", err)
	}
	if err := s.WritePacket(ctx, v4); err != nil {
		t.Fatal(err)
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1500)
	n, _, err := listener.ReadFrom(buf)
	if err != nil || n != len(v4)+data.Overhead || binary.BigEndian.Uint32(buf[4:8]) != 1 {
		t.Fatalf("IPv4 write or packet ID: n=%d err=%v", n, err)
	}
	frame, err := peer.Seal(v6)
	if err != nil {
		t.Fatal(err)
	}
	s.receive(frame)
	if len(s.inbound) != 0 || !s.lastRecv.IsZero() {
		t.Fatal("blocked IPv6 was delivered or refreshed liveness")
	}
	frame, err = peer.Seal(v4)
	if err != nil {
		t.Fatal(err)
	}
	s.receive(frame)
	if len(s.inbound) != 1 || len(<-s.inbound) != len(v4) {
		t.Fatal("IPv4 rejected")
	}
	s.info.Tunnel.BlockIPv6 = false
	frame, err = peer.Seal(v6)
	if err != nil {
		t.Fatal(err)
	}
	s.receive(frame)
	if len(s.inbound) != 1 || len(<-s.inbound) != len(v6) {
		t.Fatal("IPv6 rejected without block policy")
	}
}
