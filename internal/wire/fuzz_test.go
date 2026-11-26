package wire

import (
	"bytes"
	"testing"
)

func FuzzControlPacket(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{byte(DataV2) << 3})
	for _, packet := range []ControlPacket{
		{Header: Header{Opcode: ClientReset}, Sender: SessionID{1}},
		{Header: Header{Opcode: Control, KeyID: 7}, Sender: SessionID{2}, ID: 3, Payload: []byte{4, 5}},
		{Header: Header{Opcode: ACK}, ACKTarget: SessionID{1}, ACKCount: MaxACKs},
	} {
		prefix, err := packet.AppendPrefix(nil)
		if err != nil {
			f.Fatal(err)
		}
		raw, err := packet.AppendBody(prefix)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
		f.Add(raw[:len(raw)-1])
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65535 {
			return
		}
		header, headerErr := ParseHeader(raw)
		if headerErr == nil {
			first, err := header.Byte()
			if err != nil || first != raw[0] {
				t.Fatal("accepted header did not round-trip")
			}
		}
		n := min(PrefixSize, len(raw))
		packet, err := ParseControl(raw[:n], raw[n:])
		if err != nil {
			return
		}
		if headerErr != nil || packet.Header != header || packet.IsData() {
			t.Fatal("control and header decoders disagree")
		}
		prefix, err := packet.AppendPrefix(nil)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := packet.AppendBody(prefix)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatal("accepted control packet did not round-trip")
		}
	})
}
