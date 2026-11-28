package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"
)

func questionPacket(name []byte) []byte {
	header := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	return append(append(header, name...), 0, 1, 0, 1)
}

func TestExchangeDNSRejectsCompressedQuestion(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		name := "udp"
		if tcp {
			name = "tcp"
		}
		t.Run(name, func(t *testing.T) {
			server := netip.MustParseAddrPort("10.33.0.1:15353")
			a := localStack(t, Config{Addresses: []netip.Prefix{netip.MustParsePrefix("10.33.0.2/24")},
				DNSServers: []netip.AddrPort{server}})
			malformed := questionPacket([]byte{3, 1, 'a', 0, 0xc0, 13})
			if _, err := a.ExchangeDNS(t.Context(), server, malformed); !errors.Is(err, ErrDNS) {
				t.Fatalf("compressed query = %v", err)
			}
			peer := localStack(t, Config{Addresses: []netip.Prefix{netip.MustParsePrefix("10.33.0.1/24")}})
			pipeStacks(t, a, peer)
			udp, listener := testUDP(t, peer, server), testTCP(t, peer, server)
			query := questionPacket([]byte{3, 1, 'a', 0, 1, 'a', 0})
			response := bytes.Clone(malformed)
			response[2] |= 0x80
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			served := make(chan error, 1)
			go func() {
				udp.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, len(query))
				_, source, err := udp.ReadFrom(buf)
				if err != nil {
					served <- err
					return
				}
				if !tcp {
					_, err = udp.WriteTo(response, source)
					served <- err
					return
				}
				buf[2] |= 0x82
				if _, err = udp.WriteTo(buf, source); err != nil {
					served <- err
					return
				}
				conn, err := listener.Accept()
				if err != nil {
					served <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err = io.ReadFull(conn, make([]byte, 2+len(query))); err == nil {
					wire := binary.BigEndian.AppendUint16(nil, uint16(len(response)))
					_, err = conn.Write(append(wire, response...))
				}
				served <- err
			}()
			if _, err := a.ExchangeDNS(ctx, server, query); !errors.Is(err, ErrDNS) {
				t.Fatalf("compressed response = %v", err)
			}
			select {
			case err := <-served:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

func TestDNSQuestionLiteralLabels(t *testing.T) {
	literal := questionPacket([]byte{4, 1, 'A', 0, 0xff, 0})
	folded := questionPacket([]byte{4, 1, 'a', 0, 0xff, 0})
	one, ok := dnsQuestionOf(literal)
	two, okTwo := dnsQuestionOf(folded)
	if !ok || !okTwo || one != two {
		t.Fatal("valid literal binary label or ASCII case fold was rejected")
	}
	for tail := 1; tail <= 3; tail += 2 {
		other := bytes.Clone(literal)
		other[len(other)-4+tail]++
		if next, ok := dnsQuestionOf(other); !ok || next == one {
			t.Fatal("question type or class did not take part in comparison")
		}
	}
	if root, ok := dnsQuestionOf(questionPacket([]byte{0})); !ok || root == one {
		t.Fatal("root question was not accepted")
	}
	for _, name := range [][]byte{
		{3, 1, 'a', 0, 0xc0, 13}, // inside label payload
		{0xc0, 2},                // header
		{0xc0, 16, 0},            // forward
		{0xc0, 12},               // self-reference
		{0xc0},                   // incomplete pointer
		{63, 'a'},                // truncated label
		{0x40, 0},                // extended label
	} {
		if _, ok := dnsQuestionOf(questionPacket(name)); ok {
			t.Fatalf("accepted malformed QNAME %x", name)
		}
	}
}

func FuzzDNSQuestionLiteral(f *testing.F) {
	f.Add(questionPacket([]byte{0}))
	f.Add(questionPacket([]byte{3, 'V', 'P', 'n', 0}))
	f.Add(questionPacket([]byte{3, 1, 'a', 0, 0xc0, 13}))
	f.Fuzz(func(t *testing.T, message []byte) {
		if len(message) > maxDNSPacket {
			return
		}
		question, ok := dnsQuestionOf(message)
		if !ok {
			return
		}
		name := question.name[:]
		for len(name) != 0 && name[0] != 0 {
			n := int(name[0])
			if n > 63 || n >= len(name) {
				t.Fatal("parser accepted a nonliteral question")
			}
			name = name[1+n:]
		}
		if len(name) == 0 {
			t.Fatal("parser accepted an unterminated question")
		}
	})
}
