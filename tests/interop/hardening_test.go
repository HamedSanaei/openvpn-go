//go:build linux

package interop_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

func TestTLSAuthVariantsOpenVPN26(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, binary, pki)
	for _, network := range []string{"udp", "tcp"} {
		for _, digest := range []string{"SHA1", "SHA256", "SHA384", "SHA512"} {
			t.Run(network+"/"+digest, func(t *testing.T) {
				direction := client.KeyBidirectional
				args := []string{"--auth", digest, "--tls-auth", "shared.key"}
				if digest == "SHA384" || digest == "SHA512" {
					args = append(args, "1")
					direction = client.KeyDirection0
				}
				port := f.start(t, network, "tls", false, args...)
				cfg := f.config(pki, network, "tls", port, false)
				cfg.Control = client.ControlProtection{
					Mode: client.ControlTLSAuth, Key: f.key("shared.key"), Digest: digest, Direction: direction,
				}
				if info := connect(t, cfg); info.DataCipher != "AES-256-GCM" {
					t.Fatalf("invalid data cipher: %s", info.DataCipher)
				}
			})
		}
	}
}

func TestNegotiationPolicyOpenVPN26(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, binary, pki)
	t.Run("reject_compression_push", func(t *testing.T) {
		port := f.start(t, "tcp", "tls", false, "--push", "compress stub-v2")
		cfg := f.config(pki, "tcp", "tls", port, false)
		cfg.Endpoints = append(cfg.Endpoints, cfg.Endpoints[0])
		c, err := client.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		assertInteropCode(t, c.Connect(t.Context()), client.CodeProtocol)
		if c.Stats().Attempts != 1 || c.Stats().Connections != 0 {
			t.Fatal("unsupported push permitted fallback or authenticated forwarding")
		}
	})
	t.Run("reject_cipher_mismatch", func(t *testing.T) {
		port := f.start(t, "tcp", "tls", false)
		cfg := f.config(pki, "tcp", "tls", port, false)
		cfg.Endpoints = append(cfg.Endpoints, cfg.Endpoints[0])
		cfg.DataCiphers = []string{"AES-128-GCM"}
		c, err := client.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		err = c.Connect(t.Context())
		var result *client.Error
		// The peer can abort via AUTH_FAILED or send a disallowed cipher.
		if !errors.As(err, &result) || result.Code != client.CodeAuthentication && result.Code != client.CodeProtocol ||
			c.Stats().Attempts != 1 || c.Stats().Connections != 0 {
			t.Fatalf("cipher mismatch: %v, %+v", err, c.Stats())
		}
	})
	t.Run("optional_transport_hints", func(t *testing.T) {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(network, func(t *testing.T) {
				port, echo := startDataPeer(t, f, network, "tls-crypt", true, "1.3", "AES-256-GCM",
					"--push", "explicit-exit-notify", "--push", "socket-flags TCP_NODELAY",
					"--push", "sndbuf 524288", "--push", "rcvbuf 524288")
				cfg := f.config(pki, network, "tls-crypt", port, true)
				c, app := connectData(t, cfg)
				info, ok := c.ControlInfo()
				if !ok || info.DataCipher != "AES-256-GCM" {
					t.Fatal("missing negotiated AEAD")
				}
				roundtrip(t, app, echo, info.TunnelIP.AsSlice(), []byte("authenticated transport hints"))
			})
		}
	})
	t.Run("honor_ping_exit", func(t *testing.T) {
		port := f.start(t, "tcp", "tls", false, "--push", "ping-exit 1")
		cfg := f.config(pki, "tcp", "tls", port, false)
		cfg.Endpoints = append(cfg.Endpoints, cfg.Endpoints[0])
		c, err := client.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		defer cancel()
		if err := c.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		device, app := testkit.PacketPipe(0, transport.DefaultPacketSize)
		defer app.Close()
		assertInteropCode(t, c.Run(ctx, device), client.CodePeerStopped)
		if c.Stats().Attempts != 1 || c.Stats().Reconnects != 0 {
			t.Fatal("client reconnected after a peer-requested exit")
		}
	})
}

func assertInteropCode(t *testing.T, err error, code client.ErrorCode) {
	t.Helper()
	var actual *client.Error
	if !errors.As(err, &actual) || actual.Code != code || strings.Contains(err.Error(), "compress") {
		t.Fatalf("got %v, expected redacted %q", err, code)
	}
}
