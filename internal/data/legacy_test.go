package data

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
)

func TestExplicitDataV1(t *testing.T) {
	for _, cipher := range []string{crypt.AES128GCM, crypt.AES256GCM} {
		for _, udp := range []bool{false, true} {
			keys := testKeys(t, cipher, 1)
			tx, err := NewChannelForFormat(0, udp, keys, true)
			if err != nil {
				t.Fatal(err)
			}
			keys.Send, keys.Receive = keys.Receive, keys.Send
			rx, err := NewChannelForFormat(0, udp, keys, true)
			if err != nil {
				t.Fatal(err)
			}
			modern, err := NewChannel(0, udp, keys)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewChannelForFormat(7, udp, keys, true); err == nil {
				t.Fatal("peer ID accepted in DATA_V1")
			}
			payload := []byte("synthetic IP packet")
			raw, err := tx.Seal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != len(payload)+21 || raw[0] != byte(wire.DataV1)<<3 || binary.BigEndian.Uint32(raw[1:5]) != 1 {
				t.Fatal("DATA_V1 framing")
			}
			now := time.Now()
			reject(t, modern, raw, now)
			for _, i := range []int{0, 1, 5, 21} {
				bad := bytes.Clone(raw)
				bad[i] ^= 1
				reject(t, rx, bad, now)
			}
			for i := range len(raw) {
				reject(t, rx, raw[:i], now)
			}
			got, err := rx.Open(raw, now)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("valid DATA_V1: %v", err)
			}
			reject(t, rx, raw, now)
		}
	}
}
