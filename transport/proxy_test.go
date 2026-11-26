package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPProxyDialerPreservesPacketFraming(t *testing.T) {
	proxy, remote := net.Pipe()
	defer remote.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	dialer := (SocketDialer{MaxPacketSize: 8}).WithDialContext(func(dialCtx context.Context, network, address string) (net.Conn, error) {
		if dialCtx != ctx || network != "tcp6" || address != "[2001:db8::1]:443" {
			t.Fatal("proxy dialer did not receive the original dial arguments")
		}
		return proxy, nil
	})
	packets, err := dialer.DialPacket(ctx, "tcp6", "[2001:db8::1]:443")
	if err != nil {
		t.Fatal(err)
	}
	defer packets.Close()
	remote.SetDeadline(time.Now().Add(time.Second))
	peer := make(chan error, 1)
	go func() {
		wire := make([]byte, 5)
		if _, err := io.ReadFull(remote, wire); err != nil {
			peer <- err
			return
		}
		if !bytes.Equal(wire, []byte{0, 3, 1, 2, 3}) {
			peer <- errors.New("invalid OpenVPN TCP framing")
			return
		}
		_, err := remote.Write([]byte{0, 2, 4, 5})
		peer <- err
	}()
	if err := packets.WritePacket(ctx, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	assertPacket(t, ctx, packets, []byte{4, 5})
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
}

func TestProxyAdapterClosesPartialDial(t *testing.T) {
	for _, cancelDuringDial := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		local, remote := net.Pipe()
		failed := errors.New("synthetic proxy dial failure")
		d := (SocketDialer{}).WithDialContext(func(context.Context, string, string) (net.Conn, error) {
			if cancelDuringDial {
				cancel()
				return local, nil
			}
			return local, failed
		})
		if cancelDuringDial {
			failed = context.Canceled
		}
		if packets, err := d.DialPacket(ctx, "tcp", "remote.example.test:443"); packets != nil || !errors.Is(err, failed) {
			t.Fatalf("partial dial got %v, %v", packets, err)
		}
		remote.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("failed proxy connection remained open: %v", err)
		}
		remote.Close()
		cancel()
	}
}
