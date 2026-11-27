//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/internal/wire"
	"github.com/hamedsanaei/openvpn-go/transport"
)

// TestLossySessionSoak uses a seeded local datagram relay on both sides of
// the established protocol. Nightly runs increase the sample size.
func TestLossySessionSoak(t *testing.T) {
	binaryPath := interopPeer(t)
	seed := uint64(34)
	if raw := os.Getenv("OPENVPN_SOAK_SEED"); raw != "" {
		var err error
		seed, err = strconv.ParseUint(raw, 10, 64)
		if err != nil {
			t.Fatal("invalid soak seed")
		}
	}
	long := os.Getenv("OPENVPN_SOAK_LONG") == "1"
	sessions, packets := 2, 96
	if long {
		sessions, packets = 4, 400
	}
	pki := testkit.NewPKI(t)
	fixture := makePKIFixture(t, binaryPath, pki)
	port, echo := startDataPeer(t, fixture, "udp", "tls", false, "1.2", "AES-256-GCM", "--duplicate-cn")
	go func() {
		var buffer [1536]byte
		for {
			n, from, err := echo.ReadFromUDP(buffer[:])
			if err != nil {
				return
			}
			echo.WriteToUDP(buffer[:n], from)
		}
	}()
	start := time.Now()
	t.Cleanup(func() {
		runtime.GC()
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		t.Logf("seed=%d leases=%d packets_per_lease=%d elapsed=%s heap_bytes=%d goroutines=%d",
			seed, sessions, packets, time.Since(start), mem.HeapAlloc, runtime.NumGoroutine())
		if mem.HeapAlloc > 64<<20 {
			t.Fatal("post-soak heap exceeded 64 MiB")
		}
	})
	for index := range sessions {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			t.Parallel()
			relay, err := testkit.NewRelay(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}, seed+uint64(index))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(relay.Close)
			cfg := fixture.config(pki, "udp", "tls", uint16(relay.Address().Port), false)
			cfg.RekeyInterval = 2 * time.Second
			c, app := connectData(t, cfg)
			t.Cleanup(func() {
				if t.Failed() {
					for _, report := range c.RekeyReports() {
						t.Logf("rekey generation=%d key=%d phase=%s duration=%s code=%s",
							report.Generation, report.KeyID, report.Phase, report.Duration, report.Code)
					}
				}
			})
			info, ok := c.ControlInfo()
			if !ok || !info.TunnelIP.Is4() {
				t.Fatal("no authenticated address")
			}
			dst := echo.LocalAddr().(*net.UDPAddr)
			var received, missed, checkpoint int
			seen := make(map[int]bool, packets)
			var buf [1600]byte
			var seedPayload [256]byte
			binary.BigEndian.PutUint64(seedPayload[4:12], seed+uint64(index))
			for seq := range packets {
				binary.BigEndian.PutUint32(seedPayload[:4], uint32(seq))
				packet := ipv4UDP(info.TunnelIP.AsSlice(), dst.IP.To4(), uint16(26000+index), uint16(dst.Port), seedPayload[:])
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				if err := app.WritePacket(ctx, packet); err != nil {
					cancel()
					t.Fatal(err)
				}
				for {
					n, err := app.ReadPacket(ctx, buf[:])
					if errors.Is(err, context.DeadlineExceeded) {
						missed++
						break
					}
					if err != nil {
						cancel()
						t.Fatal(err)
					}
					// Linux may emit IPv6 multicast discovery on the test
					// link. This workload only sends IPv4 UDP.
					if n >= 48 && buf[0]>>4 == 6 && buf[6] == 58 && buf[24] == 0xff {
						continue
					}
					if n != 28+len(seedPayload) || !bytes.Equal(buf[32:n], seedPayload[4:]) {
						cancel()
						t.Fatalf("unexpected authenticated payload: n=%d IP-protocol=%d source=%v destination=%v source-port=%d destination-port=%d",
							n, buf[9], buf[12:16], buf[16:20], binary.BigEndian.Uint16(buf[20:22]), binary.BigEndian.Uint16(buf[22:24]))
					}
					got := int(binary.BigEndian.Uint32(buf[28:32]))
					if got < 0 || got > seq || seen[got] {
						cancel()
						t.Fatal("replay or invalid sequence reached the tunnel")
					}
					seen[got] = true
					received++
					if got == seq {
						break
					}
				}
				cancel()
				if long && (seq == packets/3 || seq == 2*packets/3 || seq == packets-1) {
					if received == checkpoint {
						t.Fatal("no validated traffic in a rekey phase")
					}
					checkpoint = received
				}
				if seq == packets/3 {
					if info, _ := c.ControlInfo(); info.KeyID == 0 {
						waitForKeyID(t, c, 1)
					}
				}
				if seq == 2*packets/3 {
					if info, ok := c.ControlInfo(); !ok || info.KeyID == 0 {
						t.Fatal("rekey did not survive impairment")
					}
					if info, _ := c.ControlInfo(); info.KeyID == 1 {
						waitForKeyID(t, c, 2)
					}
				}
			}
			stats := relay.Stats()
			t.Logf("seed=%d received=%d missed=%d relay=%+v", seed+uint64(index), received, missed, stats)
			minimum := packets / 2
			if long {
				minimum = packets * 7 / 10
			}
			if received < minimum || stats[0].Lost+stats[1].Lost == 0 ||
				stats[0].Duplicated+stats[1].Duplicated == 0 ||
				stats[0].Reordered+stats[1].Reordered == 0 ||
				stats[0].PeakQueued > testkit.RelayCapacity || stats[1].PeakQueued > testkit.RelayCapacity {
				t.Fatal("insufficient delivery or impairment coverage")
			}
		})
	}
}

func TestUDPRekeyRecoversLostPreviousACK(t *testing.T) {
	pki := testkit.NewPKI(t)
	fixture := makePKIFixture(t, interopPeer(t), pki)
	port, echo := startDataPeer(t, fixture, "udp", "tls", false, "1.2", "AES-256-GCM", "--reneg-sec", "0")
	cfg := fixture.config(pki, "udp", "tls", port, false)
	cfg.RekeyInterval = time.Second
	var loss previousACKLoss
	cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, network, address string) (transport.PacketConn, error) {
		conn, err := (transport.SocketDialer{}).DialPacket(ctx, network, address)
		if err != nil {
			return nil, err
		}
		loss.PacketConn = conn
		return &loss, nil
	})
	c, app := connectData(t, cfg)
	initial, ok := c.ControlInfo()
	if !ok || !initial.TunnelIP.Is4() {
		t.Fatal("initial generation was not authenticated")
	}
	waitForKeyID(t, c, 1)
	if loss.dropped.Load() == 0 {
		t.Fatal("the test did not lose the key-1 acknowledgement")
	}
	waitForKeyID(t, c, 2)
	if !loss.lateACK.Load() || c.Stats().Connections != 1 {
		t.Fatal("the previous control ACK was not recovered on the same connection")
	}
	roundtrip(t, app, echo, initial.TunnelIP.AsSlice(), []byte("authenticated data after the second rekey"))
}

type previousACKLoss struct {
	transport.PacketConn
	keyTwo  bool // Only the mux write gate accesses this flag.
	dropped atomic.Uint64
	lateACK atomic.Bool
}

func (p *previousACKLoss) WritePacket(ctx context.Context, packet []byte) error {
	header, err := wire.ParseHeader(packet)
	if err == nil && header.KeyID == 2 && header.Opcode == wire.SoftReset {
		p.keyTwo = true
	}
	if err == nil && header.KeyID == 1 && header.Opcode == wire.ACK && len(packet) > wire.PrefixSize {
		ack, err := wire.ParseControl(packet[:wire.PrefixSize], packet[wire.PrefixSize:])
		// In the pinned TLS 1.2 fixture, server packet 3 ends the first
		// rekey. Hold its ACK until after the next local reset is sent.
		if err == nil && slices.Contains(ack.ACKs[:ack.ACKCount], uint32(3)) {
			if !p.keyTwo {
				p.dropped.Add(1)
				return nil
			}
			p.lateACK.Store(true)
		}
	}
	return p.PacketConn.WritePacket(ctx, packet)
}
