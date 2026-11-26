package data

import (
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
)

func BenchmarkDataRoundTrip(b *testing.B) {
	for _, cipher := range []string{crypt.AES128GCM, crypt.AES256GCM, crypt.ChaCha20Poly1305} {
		b.Run(cipher, func(b *testing.B) {
			keys := testKeys(b, cipher, 17)
			tx, err := NewChannel(7, true, keys)
			if err != nil {
				b.Fatal(err)
			}
			keys.Send, keys.Receive = keys.Receive, keys.Send
			rx, err := NewChannel(7, true, keys)
			if err != nil {
				b.Fatal(err)
			}
			payload := make([]byte, 1400)
			now := time.Unix(1700, 0)
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				wire, err := tx.Seal(payload)
				if err != nil {
					b.Fatal(err)
				}
				if opened, err := rx.Open(wire, now); err != nil || len(opened) != len(payload) {
					b.Fatalf("failed test packet recovery: %v", err)
				}
			}
		})
	}
}

func BenchmarkDiscardUnauthenticated(b *testing.B) {
	keys := testKeys(b, crypt.AES256GCM, 17)
	tx, err := NewChannel(7, true, keys)
	if err != nil {
		b.Fatal(err)
	}
	packet, err := tx.Seal(make([]byte, 1400))
	if err != nil {
		b.Fatal(err)
	}
	packet[8] ^= 1
	keys.Send, keys.Receive = keys.Receive, keys.Send
	rx, err := NewChannel(7, true, keys)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Unix(1700, 0)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := rx.Open(packet, now); err == nil {
			b.Fatal("modified packet passed authentication")
		}
	}
}
