package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
)

func TestDirectionalControlProtection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   Mode
		dir    Direction
		digest string
	}{
		{"tls-auth SHA256", TLSAuth, Direction1, "SHA256"},
		{"tls-auth SHA1 bidirectional", TLSAuth, Bidirectional, "SHA1"},
		{"tls-crypt", TLSCrypt, Bidirectional, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, 256)
			for i := range key {
				key[i] = byte(i)
			}
			data := []byte("OpenVPN synthetic key\n-----BEGIN OpenVPN Static key V1-----\n" + hex.EncodeToString(key) + "\n-----END OpenVPN Static key V1-----\n")
			p, err := NewProtection(tc.mode, tc.dir, tc.digest, data)
			if err != nil {
				t.Fatal(err)
			}
			client := newCodec(p, 400)
			p.rx, p.tx = p.tx, p.rx
			server := newCodec(p, 500)
			message := wire.ControlPacket{Header: wire.Header{Opcode: wire.Control}, Sender: wire.SessionID{1}, ID: 3, Payload: []byte("TLS record bytes")}
			packet, err := client.seal(message)
			if err != nil {
				t.Fatal(err)
			}
			out, counter, stamp, err := server.open(packet)
			if err != nil || counter != 1 || stamp != 400 || out.ID != 3 || !bytes.Equal(out.Payload, message.Payload) {
				t.Fatalf("unprotect = %+v, %d, %d, %v", out, counter, stamp, err)
			}
			packet[len(packet)-1] ^= 1
			if _, _, _, err := server.open(packet); !errors.Is(err, wire.ErrPacket) {
				t.Fatal("altered control packet accepted")
			}
		})
	}
}

func TestReceiveOrderAndACKBinding(t *testing.T) {
	self, remote := testkit.PacketPipe(8, 512)
	d := newDriver(self, &frameProtection{codec: newCodec(Protection{}, 0)}, true)
	d.local = wire.SessionID{1}
	peer := wire.SessionID{2}
	ctx := t.Context()
	if err := d.enqueue(ctx, wire.ClientReset, nil); err != nil {
		t.Fatal(err)
	}
	readTestPacket(t, remote)
	peerCodec := newCodec(Protection{}, 0)
	put := func(p wire.ControlPacket) {
		t.Helper()
		packet, err := peerCodec.seal(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := d.receive(ctx, packet); err != nil {
			t.Fatal(err)
		}
	}
	p := wire.ControlPacket{Header: wire.Header{Opcode: wire.ServerReset}, Sender: peer, ACKCount: 1, ACKTarget: wire.SessionID{7}}
	put(p)
	if d.bound || len(d.tx) != 1 {
		t.Fatal("reset with wrong ACK target changed state")
	}
	p.ACKTarget = d.local
	put(p)
	readTestPacket(t, remote)
	if !d.bound || d.recvID != 1 || len(d.tx) != 0 {
		t.Fatal("valid peer reset did not initialize the control state")
	}

	put(wire.ControlPacket{Header: wire.Header{Opcode: wire.Control}, Sender: peer, ID: 2, Payload: []byte("second")})
	if _, ok := d.rx[d.recvID]; ok {
		t.Fatal("out-of-order message was ready for delivery")
	}
	put(wire.ControlPacket{Header: wire.Header{Opcode: wire.Control}, Sender: peer, ID: 1, Payload: []byte("first")})
	for _, value := range []string{"first", "second"} {
		if string(d.rx[d.recvID]) != value {
			t.Fatalf("sequence %d = %q; want %q", d.recvID, d.rx[d.recvID], value)
		}
		d.received()
	}

	if err := d.enqueue(ctx, wire.Control, []byte("outstanding")); err != nil {
		t.Fatal(err)
	}
	raw := readTestPacket(t, remote)
	ackList, err := wire.ParseControl(raw[:wire.PrefixSize], raw[wire.PrefixSize:])
	if err != nil || ackList.ACKCount != 3 || ackList.ACKTarget != peer {
		t.Fatalf("piggyback ACKs = %+v, %v", ackList, err)
	}

	ack := wire.ControlPacket{Header: wire.Header{Opcode: wire.ACK}, Sender: peer, ACKCount: 1, ACKTarget: d.local}
	ack.ACKs[0] = 7
	put(ack)
	if len(d.tx) != 1 {
		t.Fatal("unsent packet ID cleared an outstanding message")
	}
	ack.ACKs[0] = 1
	put(ack)
	if len(d.tx) != 0 {
		t.Fatal("valid ACK did not retire the outstanding message")
	}
}

func TestInitialSplitResetACK(t *testing.T) {
	for _, ackFirst := range []bool{false, true} {
		self, remote := testkit.PacketPipe(8, 512)
		d := newDriver(self, &frameProtection{codec: newCodec(Protection{}, 0)}, true)
		d.local = wire.SessionID{1}
		ctx := t.Context()
		if err := d.enqueue(ctx, wire.ClientReset, nil); err != nil {
			t.Fatal(err)
		}
		readTestPacket(t, remote)
		peer := wire.SessionID{2}
		codec := newCodec(Protection{}, 0)
		reset := wire.ControlPacket{Header: wire.Header{Opcode: wire.ServerReset}, Sender: peer}
		ack := wire.ControlPacket{Header: wire.Header{Opcode: wire.ACK}, Sender: peer, ACKCount: 1, ACKTarget: d.local}
		deliver := func(p wire.ControlPacket) {
			t.Helper()
			raw, err := codec.seal(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.receive(ctx, raw); err != nil {
				t.Fatal(err)
			}
		}
		if ackFirst {
			deliver(ack)
			wrong := reset
			wrong.Sender = wire.SessionID{3}
			deliver(wrong)
		} else {
			deliver(reset)
			wrong := ack
			wrong.ACKTarget = wire.SessionID{3}
			deliver(wrong)
			wrong.ACKTarget, wrong.Sender = d.local, wire.SessionID{3}
			deliver(wrong)
		}
		if d.bound || len(d.tx) != 1 {
			t.Fatal("uncorrelated reset and ACK activated the stream")
		}
		if ackFirst {
			deliver(reset)
		} else {
			deliver(ack)
		}
		if !d.bound || d.peer != peer || d.recvID != 1 || len(d.tx) != 0 {
			t.Fatal("valid split reset did not initialize the control state")
		}
		for i := range 2 {
			if i != 0 {
				d.splitEcho = time.Now().Add(-ackDelay)
				deliver(reset)
			}
			raw := readTestPacket(t, remote)
			reply, _, _, err := codec.open(raw)
			if err != nil || reply.Opcode != wire.ClientReset || reply.ID != 0 ||
				reply.ACKTarget != peer || reply.ACKCount != 1 || reply.ACKs[0] != 0 {
				t.Fatal("client did not acknowledge reset zero in the matching reset frame")
			}
		}
	}
}

func TestRetransmitAndReplayWindow(t *testing.T) {
	self, remote := testkit.PacketPipe(4, 512)
	d := newDriver(self, &frameProtection{codec: newCodec(Protection{}, 0)}, true)
	d.local = wire.SessionID{1}
	if err := d.enqueue(t.Context(), wire.ClientReset, nil); err != nil {
		t.Fatal(err)
	}
	initial := readTestPacket(t, remote)
	for range maxRetransmits {
		if err := d.tick(t.Context(), d.tx[0].due); err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(initial, readTestPacket(t, remote)) != 0 {
			t.Fatal("plain retransmission changed the reliable packet")
		}
	}
	if err := d.tick(t.Context(), d.tx[0].due); !errors.Is(err, ErrReliable) {
		t.Fatalf("retry budget error = %v", err)
	}

	var replay replayWindow
	now := time.Unix(5, 0)
	for _, tc := range []struct {
		counter, epoch uint32
		ok             bool
	}{
		{10, 1, true}, {12, 1, true}, {11, 1, true}, {11, 1, false},
		{80, 1, true}, {12, 1, false}, {1, 2, true}, {81, 1, false}, {0, 2, false},
	} {
		if got := replay.accept(tc.counter, tc.epoch, now); got != tc.ok {
			t.Fatalf("replay decision for %d/%d = %v; want %v", tc.counter, tc.epoch, got, tc.ok)
		}
	}
}

func readTestPacket(t *testing.T, conn interface {
	ReadPacket(context.Context, []byte) (int, error)
}) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	buf := make([]byte, 512)
	n, err := conn.ReadPacket(ctx, buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func TestV2ResetContinuation(t *testing.T) {
	for _, resend := range []bool{false, true} {
		t.Run(strconv.FormatBool(resend), func(t *testing.T) {
			// Build the client envelope with a synthetic opaque wrapped value.
			raw := make([]byte, staticSize+sha256.Size+staticSize+3)
			for i := range raw {
				raw[i] = byte(i)
			}
			wrapped := raw[staticSize:]
			binary.BigEndian.PutUint16(wrapped[len(wrapped)-2:], uint16(len(wrapped)))
			encoded := pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 client key", Bytes: raw})
			protection, err := NewProtection(TLSCryptV2, Bidirectional, "", encoded)
			if err != nil {
				t.Fatal(err)
			}
			self, peer := testkit.PacketPipe(4, 1250)
			d := newDriver(self, &frameProtection{codec: newCodec(protection, 10)}, true)
			d.local = wire.SessionID{1}
			if err := d.enqueue(t.Context(), wire.ClientV3, nil); err != nil {
				t.Fatal(err)
			}
			initial := readTestPacket(t, peer)
			if !bytes.HasSuffix(initial, wrapped) || binary.BigEndian.Uint32(initial[wire.PrefixSize:]) != earlyCounter+1 {
				t.Fatal("initial reset omitted the wrapped key or the early negotiation counter")
			}

			protection.rx, protection.tx = protection.tx, protection.rx
			server := newCodec(protection, 11)
			p := wire.ControlPacket{Header: wire.Header{Opcode: wire.ServerReset}, Sender: wire.SessionID{2}, ACKCount: 1, ACKTarget: d.local}
			request := []byte{0, 1, 0, 2, 0, 1}
			if resend {
				p.Payload = request
			}
			reply, err := server.seal(p)
			if err != nil {
				t.Fatal(err)
			}
			bad := bytes.Clone(reply)
			bad[wire.PrefixSize+outerIDSize] ^= 1
			if err := d.receive(t.Context(), bad); err != nil || d.bound {
				t.Fatalf("unverified reset bound the peer: %v", err)
			}
			if err := d.receive(t.Context(), reply); err != nil || !d.bound {
				t.Fatalf("authenticated reset did not bind the peer: %v", err)
			}
			continuePacket := readTestPacket(t, peer)
			header, err := wire.ParseHeader(continuePacket)
			want := wire.ACK
			if resend {
				want = wire.WrappedKey
				if !bytes.HasSuffix(continuePacket, wrapped) {
					t.Fatal("continuation omitted the wrapped key")
				}
			}
			if err != nil || header.Opcode != want {
				t.Fatalf("reset continuation = %v, %v; want %d", header, err, want)
			}

			p.Payload = request
			late, err := server.seal(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.receive(t.Context(), late); err != nil {
				t.Fatal(err)
			}
			if err := d.tick(t.Context(), d.ackTime); err != nil {
				t.Fatal(err)
			}
			header, err = wire.ParseHeader(readTestPacket(t, peer))
			if err != nil || header.Opcode != wire.ACK {
				t.Fatalf("late wrapped-key request was honored: %v, %v", header, err)
			}
		})
	}
}
