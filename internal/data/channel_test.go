package data

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/crypt"
)

func TestIndependentExporterAndDataVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Version   string
		Cipher    string
		Exporter  string
		PeerID    uint32 `json:"peer_id"`
		Plaintext string
		C2S       string
		S2C       string
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil || len(fixtures) != 6 {
		t.Fatalf("read fixture set: %d vectors, %v", len(fixtures), err)
	}
	for _, vector := range fixtures {
		t.Run(vector.Version+"/"+vector.Cipher, func(t *testing.T) {
			keys, err := crypt.ExportDataKeys(func(label string, context []byte, n int) ([]byte, error) {
				if label != "EXPORTER-OpenVPN-datakeys" || context != nil || n != 256 {
					t.Fatalf("exporter arguments = %q, %x, %d", label, context, n)
				}
				return decodeHex(t, vector.Exporter), nil
			}, vector.Cipher)
			if err != nil {
				t.Fatal(err)
			}
			channel, err := NewChannel(vector.PeerID, true, keys)
			if err != nil {
				t.Fatal(err)
			}
			plain := decodeHex(t, vector.Plaintext)
			got, err := channel.Seal(plain)
			if want := decodeHex(t, vector.C2S); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("sealed = %x, %v; want %x", got, err, want)
			}
			got, err = channel.Open(decodeHex(t, vector.S2C), time.Now())
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("opened = %x, %v; want %x", got, err, plain)
			}
		})
	}
}

func TestTamperTruncationAndReplay(t *testing.T) {
	for _, cipher := range []string{crypt.AES128GCM, crypt.AES256GCM, crypt.ChaCha20Poly1305} {
		t.Run(cipher, func(t *testing.T) {
			sender, receiver := pair(t, true, cipher, 7)
			valid := seal(t, sender)
			for _, i := range []int{0, 2, 4, 8, Overhead} {
				tampered := bytes.Clone(valid)
				tampered[i] ^= 1
				reject(t, receiver, tampered, time.Now())
			}
			for i := range len(valid) {
				reject(t, receiver, valid[:i], time.Now())
			}
			for _, id := range []uint32{0, 100_000} {
				forged := bytes.Clone(valid)
				binary.BigEndian.PutUint32(forged[4:], id)
				reject(t, receiver, forged, time.Now())
			}
			if _, err := receiver.Open(valid, time.Now()); err != nil {
				t.Fatalf("forgery changed the replay state: %v", err)
			}
			reject(t, receiver, valid, time.Now())
		})
	}
}

func TestDataReplayWindow(t *testing.T) {
	now := time.Unix(100, 0)
	for _, udp := range []bool{false, true} {
		sender, receiver := pair(t, udp, crypt.AES256GCM, 8)
		first, second := seal(t, sender), seal(t, sender)
		if _, err := receiver.Open(second, now); err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.Open(first, now.Add(time.Second)); (err == nil) != udp {
			t.Fatalf("reordering: udp=%v error=%v", udp, err)
		}
		reject(t, receiver, second, now)
	}

	sender, receiver := pair(t, true, crypt.AES256GCM, 8)
	first, second, third := seal(t, sender), seal(t, sender), seal(t, sender)
	for _, item := range []struct {
		raw []byte
		at  time.Time
	}{{second, now}, {third, now.Add(14 * time.Second)}} {
		if _, err := receiver.Open(item.raw, item.at); err != nil {
			t.Fatal(err)
		}
	}
	reject(t, receiver, first, now.Add(16*time.Second))
	sender.current.sent = 100
	if _, err := receiver.Open(seal(t, sender), now.Add(17*time.Second)); err != nil {
		t.Fatal(err)
	}
	reject(t, receiver, third, now.Add(17*time.Second))
}

func TestRekeyOverlapExpiryAndRollover(t *testing.T) {
	now := time.Unix(100, 0)
	sender, receiver := pair(t, true, crypt.AES256GCM, 1)
	previous, expiring := seal(t, sender), seal(t, sender)
	rotate(t, sender, receiver, 1, 2, now.Add(2*time.Second))
	if _, err := receiver.Open(previous, now.Add(time.Second)); err != nil {
		t.Fatalf("old key during allowed overlap: %v", err)
	}
	reject(t, receiver, expiring, now.Add(2*time.Second))
	firstIDOne := seal(t, sender)
	if _, err := receiver.Open(firstIDOne, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := uint8(2); i <= 7; i++ {
		rotate(t, sender, receiver, i, i+1, now.Add(5*time.Second))
		if _, err := receiver.Open(seal(t, sender), now); err != nil {
			t.Fatal(err)
		}
	}
	rotate(t, sender, receiver, 1, 9, now.Add(5*time.Second))
	reject(t, receiver, firstIDOne, now)
	if _, err := receiver.Open(seal(t, sender), now); err != nil {
		t.Fatalf("new key with reused ID: %v", err)
	}
}

func TestSendLimitNeverWraps(t *testing.T) {
	for _, cipher := range []string{crypt.AES256GCM, crypt.ChaCha20Poly1305} {
		sender, _ := pair(t, true, cipher, 4)
		last := sender.current.keys.PacketLimit
		sender.current.sent = last - 1
		if !sender.RekeyDue() {
			t.Fatal("usage limit did not request rekey")
		}
		if got := binary.BigEndian.Uint32(seal(t, sender)[4:]); got != last {
			t.Fatalf("final packet ID = %d; want %d", got, last)
		}
		if _, err := sender.Seal([]byte{1}); !errors.Is(err, ErrKeyLimit) {
			t.Fatalf("packet ID wrapped: %v", err)
		}
	}
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testKeys(t testing.TB, cipher string, seed byte) crypt.DataKeys {
	t.Helper()
	keys, err := crypt.ExportDataKeys(func(_ string, _ []byte, n int) ([]byte, error) {
		b := make([]byte, n)
		for i := range b {
			b[i] = seed + byte(i)
		}
		return b, nil
	}, cipher)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func pair(t *testing.T, udp bool, cipher string, seed byte) (*Channel, *Channel) {
	t.Helper()
	keys := testKeys(t, cipher, seed)
	tx, err := NewChannel(7, udp, keys)
	if err != nil {
		t.Fatal(err)
	}
	keys.Send, keys.Receive = keys.Receive, keys.Send
	rx, err := NewChannel(7, udp, keys)
	if err != nil {
		t.Fatal(err)
	}
	return tx, rx
}

func rotate(t *testing.T, tx, rx *Channel, generation, seed byte, expiry time.Time) {
	t.Helper()
	keys := testKeys(t, crypt.AES256GCM, seed)
	if err := tx.Promote(generation, keys, expiry); err != nil {
		t.Fatal(err)
	}
	keys.Send, keys.Receive = keys.Receive, keys.Send
	if err := rx.Promote(generation, keys, expiry); err != nil {
		t.Fatal(err)
	}
}

func seal(t *testing.T, ch *Channel) []byte {
	t.Helper()
	packet, err := ch.Seal([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func reject(t *testing.T, ch *Channel, packet []byte, now time.Time) {
	t.Helper()
	if _, err := ch.Open(packet, now); err == nil {
		t.Fatalf("unexpected acceptance of packet %x", packet)
	}
}
