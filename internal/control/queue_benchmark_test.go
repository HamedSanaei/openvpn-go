package control

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
)

// BenchmarkReceiveMuxBurst intentionally stalls the data consumer for a
// whole burst. A control record marks its end and is delivered while the
// data queue remains full. Plain control is sufficient to measure the mux.
func BenchmarkReceiveMuxBurst(b *testing.B) {
	for _, udp := range []bool{false, true} {
		transport := "tcp"
		if udp {
			transport = "udp"
		}
		for _, capacity := range []int{16, 32, 64, 128} {
			b.Run(fmt.Sprintf("%s/%d", transport, capacity), func(b *testing.B) {
				benchmarkReceiveMuxBurst(b, udp, capacity)
			})
		}
	}
}

func benchmarkReceiveMuxBurst(b *testing.B, udp bool, capacity int) {
	const burst, frameSize = 128, 1200
	ctx, cancel := context.WithTimeout(b.Context(), time.Minute)
	defer cancel()
	raw, peer := testkit.PacketPipe(128, 2048)
	defer raw.Close()
	defer peer.Close()
	mux, err := NewMux(raw, Protection{}, 2048, udp, capacity)
	if err != nil {
		b.Fatal(err)
	}
	defer mux.Close()
	stream, err := mux.StartInitial()
	if err != nil {
		b.Fatal(err)
	}
	defer stream.Close()
	conn := stream.Conn()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(deadline)
	}
	var packet [2048]byte
	n, err := peer.ReadPacket(ctx, packet[:])
	if err != nil {
		b.Fatal(err)
	}
	codec := newCodec(Protection{}, 0)
	reset, _, _, err := codec.open(packet[:n])
	if err != nil {
		b.Fatal(err)
	}
	sender := wire.SessionID{1}
	encode := func(op wire.Opcode, id uint32, body []byte) []byte {
		packet := wire.ControlPacket{Header: wire.Header{Opcode: op}, Sender: sender,
			ID: id, Payload: body, ACKCount: 1, ACKTarget: reset.Sender}
		frame, err := codec.seal(packet)
		if err != nil {
			b.Fatal(err)
		}
		return frame
	}
	if err := peer.WritePacket(ctx, encode(wire.ServerReset, 0, nil)); err != nil {
		b.Fatal(err)
	}
	if err := stream.WaitReady(ctx); err != nil {
		b.Fatal(err)
	}
	ackDone := make(chan struct{})
	go func() {
		defer close(ackDone)
		var buffer [2048]byte
		for {
			if _, err := peer.ReadPacket(ctx, buffer[:]); err != nil {
				return
			}
		}
	}()
	defer func() { cancel(); <-ackDone }()
	data := make([]byte, frameSize)
	data[0] = byte(wire.DataV2) << 3
	var marker [1]byte
	b.ReportAllocs()
	b.SetBytes(burst * frameSize)
	var id uint32
	for b.Loop() {
		for range burst {
			if err := peer.WritePacket(ctx, data); err != nil {
				b.Fatal(err)
			}
		}
		id++
		if err := peer.WritePacket(ctx, encode(wire.Control, id, []byte{1})); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, marker[:]); err != nil {
			b.Fatal(err)
		}
		for range capacity {
			select {
			case <-mux.Data():
			case <-ctx.Done():
				b.Fatal(ctx.Err())
			}
		}
	}
	stats := mux.DataQueueStats()
	if stats.Dropped != uint64(b.N*(burst-capacity)) || stats.HighWater != uint64(capacity) {
		b.Fatalf("unexpected queue accounting: %+v", stats)
	}
	b.ReportMetric(float64(stats.Dropped)/float64(b.N), "drops/burst")
	b.ReportMetric(float64(stats.HighWater), "queue-peak")
}
