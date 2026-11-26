package control

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/hamedsanaei/openvpn-go/internal/wire"
)

func FuzzProtectedControl(f *testing.F) {
	rawKey := make([]byte, staticSize)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}
	key := []byte("-----BEGIN OpenVPN Static key V1-----\n" + hex.EncodeToString(rawKey) + "\n-----END OpenVPN Static key V1-----\n")
	protectors := make([]codec, 2)
	seeds := make([][]byte, len(protectors))
	for i, mode := range []Mode{TLSAuth, TLSCrypt} {
		p, err := NewProtection(mode, Bidirectional, "", key)
		if err != nil {
			f.Fatal(err)
		}
		protectors[i] = newCodec(p, 1700)
		packet, err := protectors[i].seal(wire.ControlPacket{
			Header: wire.Header{Opcode: wire.Control, KeyID: 1}, Sender: wire.SessionID{1},
			ID: 2, Payload: []byte{10, 11, 12},
		})
		if err != nil {
			f.Fatal(err)
		}
		seeds[i] = packet
		protectors[i].tx, protectors[i].rx = protectors[i].rx, protectors[i].tx
		if _, _, _, err := protectors[i].open(packet); err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(i), packet)
		f.Add(uint8(i), packet[:len(packet)-1])
	}
	f.Fuzz(func(t *testing.T, mode uint8, input []byte) {
		if len(input) > 65535 {
			return
		}
		i := int(mode) % len(protectors)
		reader := protectors[i]
		packet, counter, stamp, err := reader.open(input)
		if err == nil && (!bytes.Equal(input, seeds[i]) || counter != 1 || stamp != 1700 || packet.ID != 2) {
			t.Fatal("modified protected control packet passed authentication")
		}
		if reader.counter != protectors[i].counter {
			t.Fatal("input changed the transmit counter")
		}
	})
}
