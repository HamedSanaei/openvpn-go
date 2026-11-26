package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestControlLayout(t *testing.T) {
	packet := ControlPacket{
		Header: Header{Opcode: Control, KeyID: 3},
		Sender: SessionID{1, 2, 3, 4, 5, 6, 7, 8},
		ACKs:   [MaxACKs]uint32{42, 17}, ACKCount: 2, ACKTarget: SessionID{9, 8, 7, 6, 5, 4, 3, 2},
		ID: 120, Payload: []byte{0x16, 0x03, 0x03},
	}
	prefix, err := packet.AppendPrefix(nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := packet.AppendBody(nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("230102030405060708020000002a00000011090807060504030200000078160303")
	if got := append(bytes.Clone(prefix), body...); !bytes.Equal(got, want) {
		t.Fatalf("wire = %x; want %x", got, want)
	}
	p, err := ParseControl(prefix, body)
	if err != nil || p.Header != packet.Header || p.Sender != packet.Sender ||
		p.ACKCount != 2 || p.ACKs != packet.ACKs || p.ACKTarget != packet.ACKTarget ||
		p.ID != packet.ID || !bytes.Equal(p.Payload, packet.Payload) {
		t.Fatalf("decoded = %+v, %v", p, err)
	}
	for n := range len(body) - len(packet.Payload) {
		if _, err := ParseControl(prefix, body[:n]); !errors.Is(err, ErrPacket) {
			t.Fatalf("accepted truncated body of %d bytes", n)
		}
	}
}

func TestACKRejectsPayloadAndInvalidCounts(t *testing.T) {
	for _, value := range []struct {
		body []byte
		want bool
	}{
		{[]byte{0}, false},
		{[]byte{9}, false},
		{[]byte{1, 0, 0, 0, 1}, false},
		{[]byte{1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1}, true},
		{[]byte{1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9}, false},
	} {
		_, err := ParseControl([]byte{40, 2, 2, 2, 2, 2, 2, 2, 2}, value.body)
		if (err == nil) != value.want {
			t.Fatalf("ACK body %x: %v", value.body, err)
		}
	}
}
