package transport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"
)

func BenchmarkSocketEcho(b *testing.B) {
	for _, network := range []string{"tcp4", "udp4"} {
		for _, workload := range []string{"64", "256", "1400", "mixed"} {
			for _, mode := range []string{"control", "cancellable"} {
				b.Run(network+"/"+workload+"/"+mode, func(b *testing.B) {
					ctx := context.WithoutCancel(b.Context())
					if mode == "cancellable" {
						ctx = b.Context()
					}
					address := echoSocket(b, network)
					c, err := (SocketDialer{MaxPacketSize: 2048}).DialPacket(ctx, network, address)
					if err != nil {
						b.Fatal(err)
					}
					defer c.Close()
					size, _ := strconv.Atoi(workload)
					sizes := []int{size}
					if workload == "mixed" {
						sizes = []int{64, 256, 1400, 1400}
					}
					payload, read := make([]byte, 1400), make([]byte, 1400)
					var latency [4096]time.Duration
					samples := 0
					if size > 0 {
						b.SetBytes(int64(size))
					}
					b.ReportAllocs()
					for index := 0; b.Loop(); index++ {
						n := sizes[index%len(sizes)]
						var started time.Time
						if index%17 == 0 {
							started = time.Now()
						}
						if err := c.WritePacket(ctx, payload[:n]); err != nil {
							b.Fatal(err)
						}
						if got, err := c.ReadPacket(ctx, read); err != nil || got != n {
							b.Fatalf("echo read: %d, %v", got, err)
						}
						if !started.IsZero() {
							latency[samples%len(latency)] = time.Since(started)
							samples++
						}
					}
					reportEchoLatency(b, latency[:min(samples, len(latency))])
				})
			}
		}
	}
}

func reportEchoLatency(b *testing.B, samples []time.Duration) {
	slices.Sort(samples)
	for _, percentile := range []int{50, 95, 99} {
		index := (len(samples)*percentile + 99) / 100
		b.ReportMetric(float64(samples[index-1]), "p"+strconv.Itoa(percentile)+"-ns")
	}
}

func BenchmarkTCPFrameWrites(b *testing.B) {
	for _, size := range []int{64, 256, 1400} {
		for _, mode := range []string{"copy", "scatter-gather"} {
			b.Run(strconv.Itoa(size)+"/"+mode, func(b *testing.B) {
				address := echoSocket(b, "tcp4")
				conn, err := (&net.Dialer{}).DialContext(b.Context(), "tcp4", address)
				if err != nil {
					b.Fatal(err)
				}
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
					b.Fatal(err)
				}
				payload, frame, response := make([]byte, size), make([]byte, size+2), make([]byte, size+2)
				binary.BigEndian.PutUint16(frame, uint16(size))
				var vectors [2][]byte
				var buffers net.Buffers
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if mode == "copy" {
						copy(frame[2:], payload)
						if n, err := conn.Write(frame); err != nil || n != len(frame) {
							b.Fatalf("copy write: %d %v", n, err)
						}
					} else {
						vectors[0], vectors[1] = frame[:2], payload
						buffers = vectors[:]
						if n, err := buffers.WriteTo(conn); err != nil || n != int64(len(frame)) {
							b.Fatalf("vector write: %d %v", n, err)
						}
					}
					if _, err := io.ReadFull(conn, response); err != nil || binary.BigEndian.Uint16(response) != uint16(size) {
						b.Fatalf("frame echo: %v", err)
					}
				}
			})
		}
	}
}

func echoSocket(b *testing.B, network string) string {
	const loopback = "127.0.0.1:0"
	if network == "tcp4" {
		l, err := net.Listen(network, loopback)
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { l.Close() })
		go func() {
			if c, err := l.Accept(); err == nil {
				defer c.Close()
				io.Copy(c, c)
			}
		}()
		return l.Addr().String()
	}
	u, err := net.ListenUDP(network, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { u.Close() })
	go func() {
		var data [2048]byte
		for {
			n, peer, err := u.ReadFromUDPAddrPort(data[:])
			if err != nil {
				return
			}
			if _, err := u.WriteToUDPAddrPort(data[:n], peer); err != nil {
				return
			}
		}
	}()
	return u.LocalAddr().String()
}
