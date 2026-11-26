package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

func pipeStacks(t *testing.T, a, b *Adapter) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var pumps sync.WaitGroup
	for _, ends := range [][2]*Adapter{{a, b}, {b, a}} {
		pumps.Go(func() {
			packet := make([]byte, 1500)
			for {
				n, err := ends[0].ReadPacket(ctx, packet)
				if err != nil {
					if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
						t.Errorf("lab packet read: %v", err)
					}
					return
				}
				err = ends[1].WritePacket(ctx, packet[:n])
				if err != nil {
					if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
						t.Errorf("lab packet write: %v", err)
					}
					return
				}
			}
		})
	}
	t.Cleanup(func() {
		cancel()
		pumps.Wait()
	})
}

func localStack(t *testing.T, config Config) *Adapter {
	t.Helper()
	a, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func testTCP(t *testing.T, a *Adapter, addr netip.AddrPort) net.Listener {
	t.Helper()
	l, err := gonet.ListenTCP(a.stack, tcpip.FullAddress{
		NIC: nic, Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()), Port: addr.Port(),
	}, protocol(addr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func testUDP(t *testing.T, a *Adapter, addr netip.AddrPort) net.PacketConn {
	t.Helper()
	dest := tcpip.FullAddress{NIC: nic, Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()), Port: addr.Port()}
	conn, err := gonet.DialUDP(a.stack, &dest, nil, protocol(addr.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestParallelStacksAreIsolated(t *testing.T) {
	for _, tag := range []string{"first-session", "second-session"} {
		t.Run(tag, func(t *testing.T) {
			t.Parallel()
			server4 := netip.MustParseAddrPort("10.19.0.1:15353")
			server6 := netip.MustParseAddrPort("[fd19::1]:8443")
			client := localStack(t, Config{
				Addresses:  []netip.Prefix{netip.MustParsePrefix("10.19.0.2/24"), netip.MustParsePrefix("fd19::2/64")},
				DNSServers: []netip.AddrPort{server4},
			})
			peer := localStack(t, Config{
				Addresses: []netip.Prefix{netip.MustParsePrefix("10.19.0.1/24"), netip.MustParsePrefix("fd19::1/64")},
			})
			pipeStacks(t, client, peer)

			tcp := testTCP(t, peer, server6)
			udp := testUDP(t, peer, server4)
			tcpDNS := testTCP(t, peer, server4)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			request := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
			builtPacket := append(bytes.Clone(request), []byte(tag)...)
			results := make(chan error, 4)
			go func() {
				conn, err := tcp.Accept()
				if err == nil {
					defer conn.Close()
					_, err = io.WriteString(conn, tag)
				}
				results <- err
			}()
			go func() {
				var query [512]byte
				n, addr, err := udp.ReadFrom(query[:])
				if err == nil && !bytes.Equal(request, query[:n]) {
					err = ErrDNS
				}
				if err == nil {
					query[2] |= 0x82 // QR and TC ask the client to retry this endpoint over TCP.
					_, err = udp.WriteTo(query[:n], addr)
				}
				results <- err
			}()
			go func() {
				conn, err := tcpDNS.Accept()
				if err == nil {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(4 * time.Second))
					framed := make([]byte, 2+len(request))
					_, err = io.ReadFull(conn, framed)
					if err == nil && (!bytes.Equal(framed[2:], request) || int(binary.BigEndian.Uint16(framed)) != len(request)) {
						err = ErrDNS
					}
					if err == nil {
						builtPacket[2] |= 0x80
						wire := binary.BigEndian.AppendUint16(nil, uint16(len(builtPacket)))
						_, err = conn.Write(append(wire, builtPacket...))
					}
				}
				results <- err
			}()
			go func() {
				conn, err := client.DialContext(ctx, "tcp", server6.String())
				if err == nil {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(4 * time.Second))
					got := make([]byte, len(tag))
					_, err = io.ReadFull(conn, got)
					if err == nil && string(got) != tag {
						err = errors.New("TCP reply came from a different network stack")
					}
				}
				results <- err
			}()
			response, err := client.ExchangeDNS(ctx, server4, request)
			if err != nil || !bytes.HasSuffix(response, []byte(tag)) {
				t.Fatalf("UDP/TCP DNS reply = %x, %v", response, err)
			}
			for range 4 {
				select {
				case err := <-results:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
		})
	}
}

func TestDialLimitsAndCancellation(t *testing.T) {
	a := localStack(t, Config{Addresses: []netip.Prefix{netip.MustParsePrefix("10.19.0.2/24")}, MaxSockets: 1})
	ctx := t.Context()
	s, err := a.DialContext(ctx, "udp", "10.19.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.DialContext(ctx, "udp", "10.19.0.1:53"); !errors.Is(err, ErrSocketLimit) {
		t.Fatalf("socket cap = %v", err)
	}
	s.Close()
	if _, err := a.DialContext(ctx, "tcp", "localhost:53"); !errors.Is(err, ErrConfig) {
		t.Fatalf("hostname reached dialing: %v", err)
	}
	if _, err := a.ExchangeDNS(ctx, netip.MustParseAddrPort("10.19.0.1:53"), make([]byte, 12)); !errors.Is(err, ErrDNS) {
		t.Fatalf("unauthorized resolver reached dialing: %v", err)
	}

	dialCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		conn, err := a.DialContext(dialCtx, "tcp", "10.19.0.1:443")
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	packetCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if n, err := a.ReadPacket(packetCtx, make([]byte, 1500)); err != nil || n < 40 {
		t.Fatalf("expected a TCP SYN from the isolated stack: %d, %v", n, err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("in-flight dial cancellation = %v", err)
	}
	readCtx, stopRead := context.WithCancel(ctx)
	defer stopRead()
	readDone := make(chan error, 1)
	go func() {
		_, err := a.ReadPacket(readCtx, make([]byte, 1500))
		readDone <- err
	}()
	stopRead()
	select {
	case err := <-readDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("packet read cancellation = %v", err)
		}
	case <-packetCtx.Done():
		t.Fatal("packet read did not cancel")
	}

	a.Close()
	if _, err := a.ReadPacket(ctx, nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed packet endpoint = %v", err)
	}
}
