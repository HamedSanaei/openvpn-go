package session

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
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
	if got := f.open(wrap(1, 11), frame(last, 4, 5, 6, 7), mtu, now); got != nil {
		t.Fatal("early last fragment completed a packet")
	}
	for _, packet := range [][]byte{wrap(2, 10), wrap(1, 20)} {
		if got := f.open(packet, frame(first, uncompressedLZO, 1, 2, 3), mtu, now); got != nil {
			t.Fatal("fragments from unrelated datagrams were combined")
		}
	}
	if got := f.open(wrap(1, 10), frame(first, uncompressedLZO, 1, 2, 3), mtu, now); !bytes.Equal(got, []byte{1, 2, 3, 4, 5, 6, 7}) {
		t.Fatal("out-of-order fragments did not reassemble")
	}
	if got := f.open(wrap(1, 12), frame(0, 0x66, 1, 2), mtu, now); got != nil {
		t.Fatal("a compressed frame was accepted")
	}
	if got := f.open(wrap(1, 13), frame(last, 4, 5, 6, 7, 8), mtu, now); got != nil {
		t.Fatal("a malformed last fragment was accepted")
	}
	if got := f.open(wrap(1, 14), frame(0, uncompressedLZO, 1, 2), mtu, now); !bytes.Equal(got, []byte{1, 2}) {
		t.Fatal("whole datagram was not decoded")
	}
	f.expire(now.Add(fragmentTTL))
	if len(f.pending) != 0 {
		t.Fatal("incomplete datagrams did not expire")
	}
}
