package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/control"
	"github.com/hamedsanaei/openvpn-go/internal/crypt"
	"github.com/hamedsanaei/openvpn-go/internal/data"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
	"github.com/hamedsanaei/openvpn-go/tunnel"
)

func TestLegacyUDPFragmentReassembly(t *testing.T) {
	f := fragmenter{}
	now := time.Now()
	wrap := func(keyID byte, pid uint32) []byte {
		packet := make([]byte, 8)
		packet[0] = keyID
		binary.BigEndian.PutUint32(packet[4:], pid)
		return packet
	}
	frame := func(flag uint32, payload ...byte) []byte {
		return append(binary.BigEndian.AppendUint32(nil, flag), payload...)
	}
	const mtu = 7
	// The last fragment may arrive first. Records from a different key ID
	// or a different first packet ID must not complete the datagram.
	const last = 2 | 7<<2 | 1<<10 | 1<<15
	const first = 1 | 7<<2
	if got := f.open(wrap(1, 11), frame(last, 4, 5, 6, 7), 1, mtu, now); got != nil {
		t.Fatal("early last fragment completed a packet")
	}
	for _, other := range []struct {
		packet []byte
		epoch  uint64
	}{{wrap(1, 10), 8}, {wrap(1, 20), 1}} {
		if got := f.open(other.packet, frame(first, uncompressedLZO, 1, 2, 3), other.epoch, mtu, now); got != nil {
			t.Fatal("fragments from unrelated datagrams were combined")
		}
	}
	if got := f.open(wrap(1, 10), frame(first, uncompressedLZO, 1, 2, 3), 1, mtu, now); !bytes.Equal(got, []byte{1, 2, 3, 4, 5, 6, 7}) {
		t.Fatal("out-of-order fragments did not reassemble")
	}
	if got := f.open(wrap(1, 12), frame(0, 0x66, 1, 2), 1, mtu, now); got != nil {
		t.Fatal("a compressed frame was accepted")
	}
	if got := f.open(wrap(1, 13), frame(last, 4, 5, 6, 7, 8), 1, mtu, now); got != nil {
		t.Fatal("a malformed last fragment was accepted")
	}
	if got := f.open(wrap(1, 14), frame(0, uncompressedLZO, 1, 2), 1, mtu, now); !bytes.Equal(got, []byte{1, 2}) {
		t.Fatal("whole datagram was not decoded")
	}
	f.expire(now.Add(fragmentTTL))
	if len(f.pending) != 0 {
		t.Fatal("incomplete datagrams did not expire")
	}
}

func TestFragmentEncoderRecordLimit(t *testing.T) {
	keys, err := crypt.ExportDataKeys(func(_ string, _ []byte, size int) ([]byte, error) {
		return make([]byte, size), nil
	}, crypt.AES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := data.NewChannel(1, true, keys)
	if err != nil {
		t.Fatal(err)
	}
	f := fragmenter{chunkSize: 228}
	for _, size := range []int{0, 229, 65536, 228} {
		f.chunkSize = size
		if _, err := f.seal(ch, make([]byte, 228*32)); !errors.Is(err, tunnel.ErrMTUExceeded) || f.sequence != 0 {
			t.Fatalf("invalid fragment input with chunk size %d was accepted", size)
		}
	}
	wantedID := uint32(1)
	for _, count := range []int{1, 31, 32} {
		frames, err := f.seal(ch, make([]byte, 228*count-1))
		if err != nil || len(frames) != count || binary.BigEndian.Uint32(frames[0][4:8]) != wantedID {
			t.Fatalf("invalid boundary encoding for %d records: %v", count, err)
		}
		wantedID += uint32(count)
	}
}

func TestKeepaliveUsesActiveDataFraming(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		keys, err := crypt.ExportDataKeys(func(_ string, _ []byte, size int) ([]byte, error) {
			return make([]byte, size), nil
		}, crypt.AES256GCM)
		if err != nil {
			t.Fatal(err)
		}
		ch, err := data.NewChannel(1, true, keys)
		if err != nil {
			t.Fatal(err)
		}
		keys.Send, keys.Receive = keys.Receive, keys.Send
		receiver, err := data.NewChannel(1, true, keys)
		if err != nil {
			t.Fatal(err)
		}
		raw, wire := testkit.PacketPipe(1, 1400)
		mux, err := control.NewMux(raw, control.Protection{}, 1400, true, 0)
		if err != nil {
			t.Fatal(err)
		}
		s := &Session{ctx: t.Context(), channel: ch, mux: mux, writeGate: make(chan struct{}, 1),
			info: tlscontrol.Negotiation{PingInterval: time.Second}}
		want := []byte(data.Keepalive)
		if enabled {
			s.fragments = &fragmenter{chunkSize: 1280}
			want = append([]byte{0, 0, 0, 0, uncompressedLZO}, want...)
		}
		if err := s.maintain(time.Now()); err != nil {
			t.Fatal(err)
		}
		var packet [1400]byte
		n, err := wire.ReadPacket(t.Context(), packet[:])
		if err != nil {
			t.Fatal(err)
		}
		got, err := receiver.Open(packet[:n], time.Now())
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("framing enabled %t: keepalive size %d, err %v", enabled, len(got), err)
		}
		mux.Close()
		raw.Close()
		wire.Close()
	}
}
