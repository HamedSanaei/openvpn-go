package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
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
		info: tlscontrol.Negotiation{PingTimeout: time.Second},
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
}
