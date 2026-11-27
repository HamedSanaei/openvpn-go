package session

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/observability"
)

func TestBoundedAuthenticatedReceiveQueues(t *testing.T) {
	for _, udp := range []bool{false, true} {
		for _, capacity := range []int{1, 16, 32, 64, 128} {
			t.Run(fmt.Sprintf("udp=%t/capacity=%d", udp, capacity), func(t *testing.T) {
				keys, err := crypt.ExportDataKeys(func(_ string, _ []byte, n int) ([]byte, error) { return make([]byte, n), nil }, crypt.AES256GCM)
				if err != nil {
					t.Fatal(err)
				}
				ch, err := data.NewChannel(0, udp, keys)
				if err != nil {
					t.Fatal(err)
				}
				keys.Send, keys.Receive = keys.Receive, keys.Send
				peer, err := data.NewChannel(0, udp, keys)
				if err != nil {
					t.Fatal(err)
				}
				s := &Session{channel: ch, inbound: make(chan []byte, capacity), packetMTU: 1500, rotate: make(chan struct{}, 1)}
				packet := make([]byte, 40)
				packet[0] = 0x45
				binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
				for i := 0; i < 128; i++ {
					packet[20] = byte(i)
					frame, err := peer.Seal(packet)
					if err != nil {
						t.Fatal(err)
					}
					s.receive(frame)
				}
				stats := s.inboundQueue.Stats()
				if stats.Dropped != uint64(128-capacity) || stats.HighWater != uint64(capacity) {
					t.Fatalf("queue accounting: %+v", stats)
				}
				for i := 0; i < capacity; i++ {
					got := <-s.inbound
					if got[20] != byte(i) {
						t.Fatalf("drop-new policy: packet %d got %d", i, got[20])
					}
				}
				frame, err := peer.Seal(packet)
				if err != nil {
					t.Fatal(err)
				}
				s.receive(frame)
				if len(s.inbound) != 1 || s.inboundQueue.Stats() != stats {
					t.Fatal("queue did not recover after burst")
				}
			})
		}
	}
}

func TestBoundedRekeyHistory(t *testing.T) {
	s := new(Session)
	for i := 0; i < 12; i++ {
		s.recordRekey(RekeyResult{KeyID: uint8(i%7 + 1), Started: time.Now().Add(-time.Millisecond), Phase: observability.PhaseRekeyInstall})
	}
	got := s.RekeyResults()
	if len(got) != 8 {
		t.Fatalf("retained %d reports", len(got))
	}
	for i, r := range got {
		if r.KeyID != uint8((i+4)%7+1) || r.Duration <= 0 || r.Err != nil {
			t.Fatalf("report %d: %+v", i, r)
		}
	}
	got[0].KeyID = 0
	if s.RekeyResults()[0].KeyID == 0 {
		t.Fatal("history snapshot aliases storage")
	}
}
