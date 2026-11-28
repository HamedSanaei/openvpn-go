package netstack

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

type effectiveDNSDeadline struct {
	context.Context
	deadline time.Time
}

func TestExchangeDNSSilentPeerDeadline(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		name := "udp"
		if fallback {
			name = "tcp fallback"
		}
		t.Run(name, func(t *testing.T) {
			server := netip.MustParseAddrPort("10.32.0.1:15353")
			a := localStack(t, Config{Addresses: []netip.Prefix{netip.MustParsePrefix("10.32.0.2/24")},
				DNSServers: []netip.AddrPort{server}, MaxSockets: 1})
			peer := localStack(t, Config{Addresses: []netip.Prefix{netip.MustParsePrefix("10.32.0.1/24")}})
			pipeStacks(t, a, peer)
			udp, tcp := testUDP(t, peer, server), testTCP(t, peer, server)
			query := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			received := make(chan error, 1)
			go func() {
				udp.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, len(query))
				_, source, err := udp.ReadFrom(buf)
				if err != nil || !fallback {
					received <- err
					return
				}
				buf[2] |= 0x82
				if _, err = udp.WriteTo(buf, source); err != nil {
					received <- err
					return
				}
				conn, err := tcp.Accept()
				if err != nil {
					received <- err
					return
				}
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, err = io.ReadFull(conn, make([]byte, 2+len(query)))
				received <- err
				<-ctx.Done()
			}()
			if _, err := a.ExchangeDNS(ctx, server, query); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("silent DNS exchange = %v", err)
			}
			select {
			case err := <-received:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("resolver did not receive the query")
			}
			conn, err := a.DialContext(t.Context(), "udp", server.String())
			if err != nil {
				t.Fatalf("DNS exchange did not release its socket slot: %v", err)
			}
			conn.Close()
		})
	}
}

func (c effectiveDNSDeadline) Deadline() (time.Time, bool) { return c.deadline, true }

func TestDNSFailureClassification(t *testing.T) {
	life, retire := context.WithCancel(t.Context())
	defer retire()
	a := &Adapter{life: life}
	unpublished := effectiveDNSDeadline{t.Context(), time.Now().Add(-time.Second)}
	for _, tc := range []struct {
		name        string
		ctx         context.Context
		cause, want error
	}{
		{"socket timeout before context", t.Context(), errors.Join(errors.New("private detail"), os.ErrDeadlineExceeded), context.DeadlineExceeded},
		{"passed effective deadline", unpublished, net.ErrClosed, context.DeadlineExceeded},
		{"short write", t.Context(), nil, ErrDNS},
		{"short read", t.Context(), io.ErrUnexpectedEOF, ErrDNS},
		{"unrelated", t.Context(), errors.New("private detail"), ErrDNS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := a.dnsFailure(tc.ctx, tc.cause); got != tc.want {
				t.Fatalf("DNS error = %v, want %v", got, tc.want)
			}
		})
	}
	retire()
	if got := a.dnsFailure(t.Context(), os.ErrDeadlineExceeded); got != context.Canceled {
		t.Fatalf("retired adapter = %v", got)
	}
	caller, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if got := a.dnsFailure(caller, os.ErrDeadlineExceeded); got != context.DeadlineExceeded {
		t.Fatalf("caller deadline during retirement = %v", got)
	}
}
