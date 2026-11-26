//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

type interopResolver func(context.Context, string, string) ([]netip.Addr, error)

func (f interopResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestServerTrustAndExternalIdentity(t *testing.T) {
	binary := interopPeer(t)
	pki, rotation := testkit.NewPKI(t), testkit.NewPKI(t)
	f := makePKIFixture(t, binary, pki)
	port := f.start(t, "tcp", "tls", false)
	identity, err := tls.X509KeyPair(pki.Client.Certificate, pki.Client.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid", "resolved-name", "wrong-pin", "wrong-name", "revoked", "stale-crl", "wrong-issuer", "bad-password", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now()
			cfg := f.config(pki, "tcp", "tls", port, false)
			cfg.TLS.ServerFingerprints = []string{rotation.ServerFingerprint(), pki.ServerFingerprint()}
			cfg.TLS.CRL = pki.CRL(t, now, false)
			cfg.TLS.PrivateKey = nil
			var requested, signed atomic.Int32
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			cfg.TLS.KeyProvider = func(cb context.Context) (crypto.Signer, error) {
				requested.Add(1)
				switch scenario {
				case "bad-password":
					return nil, errors.New("synthetic-secret-passphrase")
				case "canceled":
					cancel()
					<-cb.Done()
					return nil, cb.Err()
				default:
					return &hardwareSigner{Signer: identity.PrivateKey.(crypto.Signer), calls: &signed}, nil
				}
			}
			want := client.CodeCertificate
			switch scenario {
			case "valid", "resolved-name":
				want = ""
			case "wrong-pin":
				cfg.TLS.ServerFingerprints = cfg.TLS.ServerFingerprints[:1]
			case "wrong-name":
				cfg.Endpoints[0].ServerName = "wrong.example.test"
			case "revoked":
				cfg.TLS.CRL = pki.CRL(t, now, true)
			case "stale-crl":
				cfg.TLS.CRL = pki.CRL(t, now.Add(-2*time.Minute), false)
			case "wrong-issuer":
				cfg.TLS.CRL = rotation.CRL(t, now, false)
			case "bad-password":
				want = client.CodeAuthentication
			case "canceled":
				want = client.CodeCanceled
			}
			if scenario == "resolved-name" {
				cfg.Endpoints[0].Host, cfg.Endpoints[0].ServerName = testkit.TestServerName, ""
				cfg.Resolver = interopResolver(func(_ context.Context, family, host string) ([]netip.Addr, error) {
					if family != "ip4" || host != testkit.TestServerName {
						return nil, errors.New("unexpected lookup")
					}
					return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
				})
			}
			c, err := client.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			err = c.Connect(ctx)
			if want == "" {
				if err != nil || requested.Load() != 1 || signed.Load() != 1 {
					t.Fatalf("external signer not used: requests=%d signatures=%d error=%v", requested.Load(), signed.Load(), err)
				}
				if ep, ok := c.ActiveEndpoint(); !ok || ep.Host != cfg.Endpoints[0].Host || ep.ServerName != testkit.TestServerName {
					t.Fatal("resolution changed the reported endpoint or TLS identity")
				}
				return
			}
			var typed *client.Error
			if !errors.As(err, &typed) || typed.Code != want || strings.Contains(err.Error(), "synthetic-secret-passphrase") ||
				signed.Load() != 0 || want == client.CodeCertificate && requested.Load() != 0 ||
				want != client.CodeCertificate && requested.Load() != 1 {
				t.Fatalf("Connect = %v, want %s; calls=%d signatures=%d", err, want, requested.Load(), signed.Load())
			}
		})
	}
}

func TestTunnelPacketMTU(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makePKIFixture(t, binary, pki)
	port, echo := startDataPeer(t, f, "udp", "tls", false, "1.2", "AES-256-GCM", "--push", "tun-mtu 1380")
	cfg := f.config(pki, "udp", "tls", port, false)
	const mtu = 1320
	cfg.TunnelMTU = mtu
	c, app := connectData(t, cfg)
	info, ok := c.ControlInfo()
	if !ok || info.Tunnel.MTU != mtu || info.MaxTunnelPacketSize != mtu {
		t.Fatalf("effective tunnel MTU = %d (packet ceiling %d)", info.Tunnel.MTU, info.MaxTunnelPacketSize)
	}
	dest := echo.LocalAddr().(*net.UDPAddr)
	source := info.TunnelIP.AsSlice()
	oversized := ipv4UDP(source, dest.IP.To4(), 26617, uint16(dest.Port), bytes.Repeat([]byte{'x'}, mtu-28+1))
	if err := app.WritePacket(t.Context(), oversized); err != nil {
		t.Fatal(err)
	}
	roundtrip(t, app, echo, source, bytes.Repeat([]byte{'y'}, mtu-28-len("response: ")))
}

type hardwareSigner struct {
	crypto.Signer
	calls *atomic.Int32
}

func (s *hardwareSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signer requires context")
}

func (s *hardwareSigner) SignContext(ctx context.Context, r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.Signer.Sign(r, digest, opts)
}

func TestExpiredTokenAndReauthentication(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makePKIFixture(t, binary, pki)
	port := f.start(t, "tcp", "tls", true, "--auth-gen-token", "1", "120", "--verb", "3")
	cfg := f.config(pki, "tcp", "tls", port, false)
	cfg.RekeyInterval = 2 * time.Second
	var calls atomic.Int32
	cfg.Authentication.Credentials = func(context.Context) (client.Credentials, error) {
		calls.Add(1)
		return client.Credentials{Username: username, Password: password}, nil
	}
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
	dev, _ := testkit.PacketPipe(1, transport.DefaultPacketSize)
	defer dev.Close()
	err = c.Run(ctx, dev)
	var failure *client.Error
	if !errors.As(err, &failure) || failure.Code != client.CodeAuthentication ||
		strings.Contains(err.Error(), password) || calls.Load() != 1 {
		t.Fatalf("expired session result = %v, credential provider calls=%d", err, calls.Load())
	}
	if err := c.Connect(ctx); err != nil || calls.Load() != 2 {
		t.Fatalf("fresh authentication = %v, credential provider calls=%d", err, calls.Load())
	}
}

func TestDeferredTextAuthentication(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makePKIFixture(t, binary, pki)
	scripts := map[string]string{
		"defer-auth": "#!/bin/sh\nprintf '5\\ncrtext\\nCR_TEXT:R:Code\\n' > \"$auth_pending_file\" || exit 1\nexit 2\n",
		"check-code": "#!/bin/sh\nif [ \"$(cat \"$1\")\" = MTIzNDU2 ]; then\n  printf 1 > \"$auth_control_file\"\nelse\n  printf 0 > \"$auth_control_file\"\nfi\n",
	}
	for name, contents := range scripts {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(contents), 0700); err != nil {
			t.Fatal(err)
		}
	}
	port := f.start(t, "tcp", "tls", false, "--script-security", "2",
		"--auth-user-pass-verify", "./defer-auth", "via-file", "--client-crresponse", "./check-code", "--verb", "3")
	for _, scenario := range []string{"success", "canceled", "rejected"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			cfg := f.config(pki, "tcp", "tls", port, true)
			calls := 0
			cfg.Authentication.Challenge = func(cb context.Context, challenge client.Challenge) (string, error) {
				calls++
				if !challenge.Required || challenge.Echo || challenge.Prompt != "Code" {
					return "", errors.New("unexpected challenge")
				}
				switch scenario {
				case "canceled":
					cancel()
					<-cb.Done()
				case "rejected":
					return "incorrect-secret", nil
				}
				return "123456", nil
			}
			c, err := client.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			err = c.Connect(ctx)
			if scenario == "success" {
				if err != nil || calls != 1 {
					t.Fatalf("deferred authentication = %v, callbacks=%d", err, calls)
				}
				return
			}
			want := client.CodeAuthentication
			if scenario == "canceled" {
				want = client.CodeCanceled
			}
			var failure *client.Error
			if !errors.As(err, &failure) || failure.Code != want || calls != 1 ||
				strings.Contains(err.Error(), "incorrect-secret") {
				t.Fatalf("deferred failure = %v, callbacks=%d, want %s", err, calls, want)
			}
		})
	}
}

func TestNegotiatedUDPExit(t *testing.T) {
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makePKIFixture(t, binary, pki)
	for _, scenario := range []string{"graceful", "dead-peer", "run-cancellation"} {
		t.Run(scenario, func(t *testing.T) {
			port := localPort(t, "udp")
			stop, logPath := f.launchArgs(t, serverArgs(port, "udp", "tls", false, "--explicit-exit-notify", "1", "--verb", "3"))
			cfg := f.config(pki, "udp", "tls", port, false)
			cfg.ExplicitExitNotify = true
			c, err := client.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := c.Connect(t.Context()); err != nil {
				t.Fatal(err)
			}
			if scenario == "run-cancellation" {
				dev, _ := testkit.PacketPipe(1, transport.DefaultPacketSize)
				defer dev.Close()
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() {
					done <- c.RunConfigured(ctx, dev, func(context.Context, client.TunnelGeneration) (func(), error) {
						cancel()
						return nil, nil
					})
				}()
				defer cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("run cancellation blocked")
				}
			} else {
				if scenario == "dead-peer" {
					stop()
				}
				before := time.Now()
				var wg sync.WaitGroup
				for range 5 {
					wg.Go(func() {
						if err := c.Close(); err != nil {
							t.Errorf("Close: %v", err)
						}
					})
				}
				wg.Wait()
				if c.State() != client.StateClosed || time.Since(before) > time.Second {
					t.Fatal("concurrent Close exceeded its budget")
				}
			}
			if scenario == "dead-peer" {
				return
			}
			for deadline := time.Now().Add(7 * time.Second); ; time.Sleep(20 * time.Millisecond) {
				raw, err := os.ReadFile(logPath)
				if err != nil {
					t.Fatal(err)
				}
				received := strings.Contains(string(raw), "CC-EEN exit message received")
				cleaned := strings.Contains(string(raw), "delayed-exit] received, client-instance exiting") ||
					strings.Contains(string(raw), "remote-exit] received, client-instance exiting")
				if cleaned || scenario == "run-cancellation" || time.Now().After(deadline) {
					want := scenario == "graceful"
					if received != want || cleaned != want {
						t.Fatalf("server observed authenticated exit=%v and cleanup=%v, scenario %s", received, cleaned, scenario)
					}
					break
				}
			}
		})
	}
}
