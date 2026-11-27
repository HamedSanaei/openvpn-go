package control

import (
	"testing"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
)

func TestFourACKCompatibilityWindow(t *testing.T) {
	self, remote := testkit.PacketPipe(16, 512)
	d := newDriver(self, &frameProtection{codec: newCodec(Protection{}, 0)}, true)
	d.ackLimit = 4
	d.local, d.peer = wire.SessionID{1}, wire.SessionID{2}
	for i := uint32(0); i < 5; i++ {
		if err := d.queueACK(t.Context(), i); err != nil {
			t.Fatal(err)
		}
	}
	p, _, _, err := d.codec.open(readTestPacket(t, remote))
	if err != nil || p.ACKCount != 4 {
		t.Fatalf("flush: count=%d err=%v", p.ACKCount, err)
	}
	if err := d.send(t.Context(), wire.ControlPacket{Header: wire.Header{Opcode: wire.ACK}}); err != nil {
		t.Fatal(err)
	}
	p, _, _, err = d.codec.open(readTestPacket(t, remote))
	if err != nil || p.ACKCount != 4 || p.ACKs[0] != 4 || p.ACKs[3] != 1 {
		t.Fatalf("window: %+v %v", p, err)
	}
}
