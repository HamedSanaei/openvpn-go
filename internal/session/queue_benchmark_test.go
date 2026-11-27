package session

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
)

// BenchmarkAuthenticatedReceiveBurst measures local AEAD and delivery
// with a stalled application until all 128 records have arrived.
func BenchmarkAuthenticatedReceiveBurst(b *testing.B) {
	for _, udp := range []bool{false, true} {
		transport := "tcp"
		if udp {
			transport = "udp"
		}
		for _, capacity := range []int{16, 32, 64, 128} {
			b.Run(fmt.Sprintf("%s/%d", transport, capacity), func(b *testing.B) {
				const burst, packetSize = 128, 1200
				keys, err := crypt.ExportDataKeys(func(_ string, _ []byte, size int) ([]byte, error) {
					return make([]byte, size), nil
				}, crypt.AES256GCM)
				if err != nil {
					b.Fatal(err)
				}
				channel, err := data.NewChannel(7, udp, keys)
				if err != nil {
					b.Fatal(err)
				}
				keys.Send, keys.Receive = keys.Receive, keys.Send
				peer, err := data.NewChannel(7, udp, keys)
				if err != nil {
					b.Fatal(err)
				}
				s := &Session{inbound: make(chan []byte, capacity), channel: channel, packetMTU: 1500,
					rotate: make(chan struct{}, 1)}
				packet := make([]byte, packetSize)
				packet[0] = 0x45
				binary.BigEndian.PutUint16(packet[2:4], packetSize)
				b.SetBytes(packetSize * burst)
				b.ReportAllocs()
				for b.Loop() {
					for range burst {
						frame, err := peer.Seal(packet)
						if err != nil {
							b.Fatal(err)
						}
						s.receive(frame)
					}
					for range capacity {
						clear(<-s.inbound)
					}
				}
				stats := s.inboundQueue.Stats()
				if stats.Dropped != uint64(b.N*(burst-capacity)) || stats.HighWater != uint64(capacity) {
					b.Fatalf("unexpected queue accounting: %+v", stats)
				}
				b.ReportMetric(float64(stats.Dropped)/float64(b.N), "drops/burst")
				b.ReportMetric(float64(stats.HighWater), "queue-peak")
			})
		}
	}
}
