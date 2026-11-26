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
	"strconv"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
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
