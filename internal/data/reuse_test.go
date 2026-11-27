package data

import (
	"bytes"
	"strconv"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
)

func TestOwnedFrameAuthenticationAndReplay(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		keys := testKeys(t, crypt.AES256GCM, 17)
		tx, _ := NewChannelForFormat(0, true, keys, legacy)
		keys.Send, keys.Receive = keys.Receive, keys.Send
		rx, _ := NewChannelForFormat(0, true, keys, legacy)
		payload := []byte("private synthetic payload")
		wire, err := tx.SealInto(make([]byte, 0, 256), payload)
		if err != nil {
			t.Fatal(err)
		}
		owned := bytes.Clone(wire)
		owned[len(owned)-1] ^= 1
		now := time.Now()
		if got, epoch, err := rx.OpenOwned(owned, now); got != nil || epoch != 0 || err != ErrPacket {
			t.Fatalf("invalid frame output: %v, %d, %v", got, epoch, err)
		}
		prefix := additionalSize
		if legacy {
			prefix = 5
		}
		if !bytes.Equal(owned[prefix:], make([]byte, len(owned)-prefix)) {
			t.Fatal("failed authentication left scratch bytes")
		}
		copy(owned, wire)
		plain, epoch, err := rx.OpenOwned(owned, now)
		if err != nil || epoch != 1 || !bytes.Equal(plain, payload) || &plain[0] != &owned[prefix] ||
			!bytes.Equal(owned[:prefix], wire[:prefix]) {
			t.Fatalf("owned frame did not preserve its prefix and payload: %v", err)
		}
		copy(owned, wire)
		if _, _, err := rx.OpenOwned(owned, now); err != ErrPacket {
			t.Fatal("authenticated frame was replayed")
		}
	}
}

func TestReusableDataAllocationBudget(t *testing.T) {
	for _, name := range []string{crypt.AES128GCM, crypt.AES256GCM, crypt.ChaCha20Poly1305} {
		t.Run(name, func(t *testing.T) {
			keys := testKeys(t, name, 17)
			tx, _ := NewChannel(7, true, keys)
			keys.Send, keys.Receive = keys.Receive, keys.Send
			rx, _ := NewChannel(7, true, keys)
			now := time.Unix(1700, 0)
			payload := make([]byte, 1400)
			frame := make([]byte, 0, len(payload)+Overhead)
			allocations := testing.AllocsPerRun(100, func() {
				packet, err := tx.SealInto(frame, payload)
				if err != nil {
					t.Fatal(err)
				}
				if plain, _, err := rx.OpenOwned(packet, now); err != nil || len(plain) != len(payload) {
					t.Fatalf("failed reusable frame: %v", err)
				}
				clear(packet)
			})
			if allocations > 1 {
				t.Fatalf("steady-state AEAD allocations = %g, maximum 1", allocations)
			}
		})
	}
}

func BenchmarkReusableDataRoundTrip(b *testing.B) {
	for _, name := range []string{crypt.AES128GCM, crypt.AES256GCM, crypt.ChaCha20Poly1305} {
		for _, size := range []int{64, 256, 1400, 65535 - Overhead} {
			b.Run(name+"/"+strconv.Itoa(size), func(b *testing.B) {
				keys := testKeys(b, name, 17)
				tx, _ := NewChannel(7, true, keys)
				keys.Send, keys.Receive = keys.Receive, keys.Send
				rx, _ := NewChannel(7, true, keys)
				payload := make([]byte, size)
				frame := make([]byte, 0, size+Overhead)
				now := time.Unix(1700, 0)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					packet, err := tx.SealInto(frame, payload)
					if err != nil {
						b.Fatal(err)
					}
					if plain, _, err := rx.OpenOwned(packet, now); err != nil || len(plain) != size {
						b.Fatalf("failed reusable frame: %v", err)
					}
					clear(packet)
				}
			})
		}
	}
}

func BenchmarkRejectDataFrame(b *testing.B) {
	for _, name := range []string{crypt.AES128GCM, crypt.AES256GCM, crypt.ChaCha20Poly1305} {
		for _, size := range []int{64, 256, 1400, 65535 - Overhead} {
			for _, mode := range []string{"invalid-tag", "replay"} {
				b.Run(name+"/"+strconv.Itoa(size)+"/"+mode, func(b *testing.B) {
					keys := testKeys(b, name, 17)
					tx, _ := NewChannel(7, true, keys)
					keys.Send, keys.Receive = keys.Receive, keys.Send
					rx, _ := NewChannel(7, true, keys)
					packet, err := tx.Seal(make([]byte, size))
					if err != nil {
						b.Fatal(err)
					}
					now := time.Unix(1700, 0)
					if mode == "replay" {
						if _, err := rx.Open(packet, now); err != nil {
							b.Fatal(err)
						}
					} else {
						packet[additionalSize] ^= 1
					}
					scratch := make([]byte, len(packet))
					b.ReportAllocs()
					for b.Loop() {
						copy(scratch, packet)
						if frame, _, err := rx.OpenOwned(scratch, now); err != ErrPacket || frame != nil {
							b.Fatalf("unexpected rejected frame: %v", err)
						}
					}
				})
			}
		}
	}
}
