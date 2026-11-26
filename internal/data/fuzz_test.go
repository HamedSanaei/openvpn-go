package data

import (
	"bytes"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
)

func FuzzDataPacket(f *testing.F) {
	keys := testKeys(f, crypt.AES256GCM, 17)
	tx, err := NewChannel(7, true, keys)
	if err != nil {
		f.Fatal(err)
	}
	known, err := tx.Seal([]byte{1, 2, 3, 4})
	if err != nil {
		f.Fatal(err)
	}
	keys.Send, keys.Receive = keys.Receive, keys.Send
	f.Add([]byte{}, false)
	f.Add(known, false)
	f.Add(known[:len(known)-1], true)
	f.Fuzz(func(t *testing.T, raw []byte, udp bool) {
		if len(raw) > 65535 {
			return
		}
		rx, err := NewChannel(7, udp, keys)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Unix(1700, 0)
		packet, err := rx.Open(raw, now)
		if err != nil {
			if packet != nil || rx.current.replay.high != 0 {
				t.Fatal("rejected packet released plaintext or advanced replay state")
			}
			packet, err = rx.Open(known, now)
		}
		if err != nil || !bytes.Equal(packet, []byte{1, 2, 3, 4}) {
			t.Fatal("known authenticated data could not be recovered")
		}
		if _, err := rx.Open(known, now); err == nil {
			t.Fatal("duplicate packet passed replay validation")
		}
	})
}
