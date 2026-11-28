package session

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
)

func TestEarlyRekeyDataIsAuthenticatedAfterPromotion(t *testing.T) {
	keys := func(seed byte) crypt.DataKeys {
		t.Helper()
		out, err := crypt.ExportDataKeys(func(_ string, _ []byte, n int) ([]byte, error) {
			return bytes.Repeat([]byte{seed}, n), nil
		}, crypt.AES256GCM)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	senderKeys := func(key crypt.DataKeys) crypt.DataKeys {
		key.Send, key.Receive = key.Receive, key.Send
		return key
	}
	for _, udp := range []bool{false, true} {
		old, next := keys(1), keys(2)
		local, err := data.NewChannel(0, udp, old)
		if err != nil {
			t.Fatal(err)
		}
		remote, err := data.NewChannel(0, udp, senderKeys(old))
		if err != nil {
			t.Fatal(err)
		}
		s := &Session{channel: local, inbound: make(chan []byte, 4), packetMTU: 1400}
		expiry := time.Now().Add(time.Minute)
		if err := remote.Promote(1, senderKeys(next), expiry); err != nil {
			t.Fatal(err)
		}
		plain := make([]byte, 40)
		plain[0] = 0x45
		binary.BigEndian.PutUint16(plain[2:4], uint16(len(plain)))
		valid, err := remote.Seal(plain)
		if err != nil {
			t.Fatal(err)
		}
		forged := bytes.Clone(valid)
		forged[len(forged)-1] ^= 1
		wrong := bytes.Clone(valid)
		wrong[0] = wrong[0]&^7 | 2
		var q earlyData
		for _, p := range [][]byte{wrong, forged, valid, bytes.Clone(valid)} {
			s.receiveDuringRekey(p, 1, &q)
		}
		if len(q.frames) != 3 || len(s.inbound) != 0 || !s.lastRecv.IsZero() {
			t.Fatalf("early ciphertext escaped its pending generation, udp=%t", udp)
		}
		for range maxEarlyRekeyFrames {
			s.receiveDuringRekey(bytes.Clone(valid), 1, &q)
		}
		if len(q.frames) != maxEarlyRekeyFrames || s.EarlyRekeyDrops() != 3 {
			t.Fatalf("pending frame count was not bounded, udp=%t", udp)
		}
		if err := local.Promote(1, next, expiry); err != nil {
			t.Fatal(err)
		}
		s.finishEarlyData(&q, time.Now())
		if len(s.inbound) != 1 || !bytes.Equal(<-s.inbound, plain) || s.EarlyRekeyDrops() != maxEarlyRekeyFrames+2 ||
			q.bytes != 0 || len(q.frames) != 0 || s.lastRecv.IsZero() {
			t.Fatalf("generation acceptance or replay accounting, udp=%t", udp)
		}
	}
}

func TestEarlyDataBoundsAndExpiry(t *testing.T) {
	q := earlyData{}
	at := time.Now()
	for i := 1; i <= maxEarlyRekeyFrames; i++ {
		q.frames = append(q.frames, earlyFrame{packet: []byte{1}, deadline: at.Add(time.Duration(i) * time.Millisecond)})
		q.bytes++
	}
	if got := q.expire(at.Add(8 * time.Millisecond)); got != 8 || q.bytes != maxEarlyRekeyFrames-8 || len(q.frames) != q.bytes {
		t.Fatalf("incorrect age or byte accounting: expired=%d queue=%+v", got, q)
	}
	if q.discard() != maxEarlyRekeyFrames-8 || len(q.frames) != 0 || q.bytes != 0 {
		t.Fatal("aborted generation retained ciphertext")
	}
}
