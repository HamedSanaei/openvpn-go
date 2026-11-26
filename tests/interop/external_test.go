//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/profile"
	"github.com/hamedsanaei/openvpn-go/transport"
)

type externalResult struct {
	Profile     []profile.CapabilityEntry `json:"profile,omitempty"`
	Warnings    []profile.CapabilityEntry `json:"warnings,omitempty"`
	Stage       string                    `json:"stage"`
	Code        string                    `json:"code,omitempty"`
	Directive   string                    `json:"directive,omitempty"`
	Line        int                       `json:"line,omitempty"`
	Transport   string                    `json:"transport,omitempty"`
	Control     string                    `json:"control,omitempty"`
	Credentials bool                      `json:"password_auth"`
	Identity    bool                      `json:"client_certificate"`
	TLS         string                    `json:"tls,omitempty"`
	AEAD        string                    `json:"aead,omitempty"`
	RoundTrips  int                       `json:"synthetic_round_trips"`
}

func TestExternalProfile(t *testing.T) {
	path := os.Getenv("OVPN_EXTERNAL_PROFILE")
	if path == "" {
		t.Skip("set OVPN_EXTERNAL_PROFILE for an authorized test profile")
	}
	want := os.Getenv("OVPN_EXTERNAL_EXPECT")
	if want == "" {
		want = "connected"
	}

	result := probeExternalProfile(t.Context(), path)
	report, err := json.Marshal(result)
	if err != nil {
		t.Fatal("could not encode redacted result")
	}
	t.Log(string(report))
	got := result.Stage
	if result.Code != "" {
		got += ":" + result.Code
	}
	if got != want {
		t.Fatalf("external profile result = %s; expected outcome did not match", got)
	}
}

func TestExternalProfileHarness(t *testing.T) {
	pki := testkit.NewPKI(t)
	f := makeFixture(t, interopPeer(t), pki)
	port, _ := startDataPeer(t, f, "tcp", "tls", true, "1.2", "AES-256-GCM")
	dir := t.TempDir()
	probe := filepath.Join(dir, "profile.ovpn")
	body := fmt.Sprintf("client\ndev tun\nremote 127.0.0.1 %d tcp4\nremote-cert-tls server\nverify-x509-name %s name\nauth-user-pass\n",
		port, testkit.TestServerName) + profilePKI(pki)
	if err := os.WriteFile(probe, []byte(body), 0600); err != nil {
		t.Fatal("could not write the generated test profile")
	}
	credentials := filepath.Join(dir, "auth")
	if err := os.WriteFile(credentials, []byte(username+"\n"+password+"\n"), 0600); err != nil {
		t.Fatal("could not write the generated test credentials")
	}
	t.Setenv("OVPN_EXTERNAL_AUTH_FILE", credentials)
	t.Setenv("OVPN_EXTERNAL_ECHO", "10.49.0.1")
	t.Setenv("OVPN_EXTERNAL_REMOTE", "1")
	t.Setenv("OVPN_EXTERNAL_ROOT", "")
	result := probeExternalProfile(t.Context(), probe)
	if result.Stage != "verified" || result.RoundTrips != 2 ||
		result.TLS != "TLS 1.2" || result.AEAD != "AES-256-GCM" || !result.Credentials || !result.Identity {
		t.Fatalf("unexpected synthetic probe result: %+v", result)
	}
}

func TestExternalProfileReportRedaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-profile-name.ovpn")
	const body = "client\ndev tun\nremote unlisted-endpoint.example.test\nsetenv HIDDEN private-secret-marker\nprivate-option example\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal("could not write the generated test profile")
	}
	t.Setenv("OVPN_EXTERNAL_ROOT", "")
	t.Setenv("OVPN_EXTERNAL_AUTH_FILE", "")
	result := probeExternalProfile(t.Context(), path)
	if result.Stage != "parse" || result.Code != string(profile.CodeUnsupported) || result.Directive != "setenv" {
		t.Fatal("expected a report of the unsupported directive")
	}
	report, err := json.Marshal(result)
	if err != nil {
		t.Fatal("could not encode the report")
	}
	for _, value := range []string{path, "unlisted-endpoint", "private-secret-marker", "private-option"} {
		if bytes.Contains(report, []byte(value)) {
			t.Fatal("external result leaked an input value")
		}
	}
}

func TestExternalProfileLegacyCipherRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-export.ovpn")
	const body = "client\ndev tun\nremote 127.0.0.1 1 tcp4\ncipher AES-256-CBC\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal("could not write generated profile")
	}
	t.Setenv("OVPN_EXTERNAL_ROOT", "")
	t.Setenv("OVPN_EXTERNAL_AUTH_FILE", "")
	result := probeExternalProfile(t.Context(), path)
	if result.Stage != "parse" || result.Code != string(profile.CodeUnsupported) || result.Directive != "cipher" {
		t.Fatal("legacy cipher must be rejected before dialing")
	}
	if result.RoundTrips != 0 || result.TLS != "" || result.AEAD != "" {
		t.Fatal("rejected profile must not claim negotiated features")
	}
}

func TestExternalCredentialsBounds(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"LF", "test-user\ntest-password\n", true},
		{"CRLF", "test-user\r\ntest-password\r\n", true},
		{"no final newline", "test-user\ntest-password", true},
		{"missing line", "test-user", false},
		{"extra line", "test-user\ntest-password\nextra", false},
		{"too large", strings.Repeat("x", 4097), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials")
			if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
				t.Fatal("could not write generated credentials")
			}
			credentials, err := readExternalCredentials(path)
			if (err == nil) != tc.valid {
				t.Fatal("unexpected credential-file validation result")
			}
			if tc.valid && (credentials.Username != "test-user" || credentials.Password != "test-password") {
				t.Fatal("unexpected credential normalization")
			}
		})
	}
}

func probeExternalProfile(ctx context.Context, name string) externalResult {
	result := externalResult{Stage: "input"}
	file, err := openExternalFile(name)
	if err != nil {
		result.Code = "profile_unavailable"
		return result
	}
	defer file.Close()
	report, _ := profile.Inspect(file)
	result.Profile = report.Entries
	if _, err := file.Seek(0, 0); err != nil {
		result.Code = "profile_unavailable"
		return result
	}
	options := profile.Options{AllowPasswordOnly: os.Getenv("OVPN_EXTERNAL_PASSWORD_ONLY") == "1"}
	if path := os.Getenv("OVPN_EXTERNAL_AUTH_FILE"); path != "" {
		options.Credentials, err = readExternalCredentials(path)
		if err != nil {
			result.Code = "credential_file_unusable"
			return result
		}
	}
	if dir := os.Getenv("OVPN_EXTERNAL_ROOT"); dir != "" {
		root, err := os.OpenRoot(dir)
		if err != nil {
			result.Code = "reference_root_unavailable"
			return result
		}
		defer root.Close()
		options.Root = root
	}
	cfg, warnings, err := profile.Parse(file, options)
	for _, warning := range warnings {
		result.Warnings = append(result.Warnings, profile.CapabilityEntry{
			Line: warning.Line, Directive: warning.Directive, Code: warning.Code, Capability: profile.Ignored,
		})
	}
	if err != nil {
		result.Stage = "parse"
		var diagnostic *profile.Diagnostic
		if errors.As(err, &diagnostic) {
			result.Code, result.Directive, result.Line = string(diagnostic.Code), diagnostic.Directive, diagnostic.Line
		}
		return result
	}

	index := 1
	if value := os.Getenv("OVPN_EXTERNAL_REMOTE"); value != "" {
		index, err = strconv.Atoi(value)
	}
	if err != nil || index < 1 || index > len(cfg.Endpoints) {
		result.Code = "invalid_remote_index"
		return result
	}
	if len(cfg.EndpointControls) != 0 {
		cfg.Control = cfg.EndpointControls[index-1]
		cfg.EndpointControls = nil
	}
	cfg.Endpoints = cfg.Endpoints[index-1 : index]
	cfg.RemoteRandom = false
	cfg.ConnectTimeout, cfg.HandshakeTimeout = 5*time.Second, 12*time.Second
	cfg.Retry = client.RetryPolicy{MaxAttempts: 1}

	peer := netip.Addr{}
	if value := os.Getenv("OVPN_EXTERNAL_ECHO"); value != "" {
		peer, err = netip.ParseAddr(value)
		if err != nil || !peer.Is4() || !peer.IsGlobalUnicast() {
			result.Code = "invalid_echo_address"
			return result
		}
	}

	result.Transport = cfg.Endpoints[0].Network
	result.Control = externalControlMode(cfg.Control.Mode)
	result.Credentials = cfg.Credentials != nil
	result.Identity = len(cfg.TLS.Certificate) != 0

	var first transport.PacketConn
	cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, network, address string) (transport.PacketConn, error) {
		link, err := (transport.SocketDialer{}).DialPacket(ctx, network, address)
		if err == nil && first == nil {
			first = link
		}
		return link, err
	})
	c, err := client.New(cfg)
	if err != nil {
		result.Stage, result.Code = "configure", externalError(err)
		return result
	}
	defer c.Close()
	if err := c.Connect(ctx); err != nil {
		result.Stage, result.Code = "connect", externalError(err)
		return result
	}
	info, ok := c.ControlInfo()
	if !ok {
		result.Stage, result.Code = "connect", "missing_negotiation"
		return result
	}
	result.Stage, result.TLS, result.AEAD = "connected", tls.VersionName(info.TLSVersion), info.DataCipher
	if peer.IsValid() {
		result.Stage, result.Code, result.RoundTrips = probeExternalData(ctx, c, first, peer)
	}
	return result
}

func openExternalFile(path string) (*os.File, error) {
	// Open non-blocking so a FIFO or device cannot stall the probe.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("expected a regular file")
	}
	return f, nil
}

func readExternalCredentials(path string) (*client.Credentials, error) {
	const maxCredentials = 4096
	f, err := openExternalFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxCredentials+1))
	defer clear(raw)
	user, rest, ok := bytes.Cut(raw, []byte{'\n'})
	pass, trailing, _ := bytes.Cut(rest, []byte{'\n'})
	if err != nil || len(raw) > maxCredentials || !ok || len(trailing) != 0 {
		return nil, errors.New("expected two bounded credential lines")
	}
	return &client.Credentials{
		Username: string(bytes.TrimSuffix(user, []byte{'\r'})),
		Password: string(bytes.TrimSuffix(pass, []byte{'\r'})),
	}, nil
}

func externalControlMode(mode client.ControlMode) string {
	switch mode {
	case client.ControlTLSAuth:
		return "tls-auth"
	case client.ControlTLSCrypt:
		return "tls-crypt"
	case client.ControlTLSCryptV2:
		return "tls-crypt-v2"
	default:
		return "plain-tls"
	}
}

func externalError(err error) string {
	var failure *client.Error
	if errors.As(err, &failure) {
		return strings.ReplaceAll(string(failure.Code), " ", "_")
	}
	return "operation_failed"
}

// When explicitly given a test-owned IPv4 echo target, exercise data on both
// sides of a transport interruption without creating an OS tunnel or routes.
func probeExternalData(ctx context.Context, c *client.Client, first transport.PacketConn, peer netip.Addr) (stage, code string, trips int) {
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	device, app := testkit.PacketPipe(8, transport.DefaultPacketSize)
	defer device.Close()
	generations := make(chan client.TunnelGeneration, 2)
	done := make(chan error, 1)
	go func() {
		done <- c.RunConfigured(ctx, device, func(ctx context.Context, next client.TunnelGeneration) (func(), error) {
			select {
			case generations <- next:
				return nil, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	}()
	stage = "traffic"
	for count := uint64(1); count <= 2; count++ {
		select {
		case err := <-done:
			return stage, externalError(err), trips
		case <-ctx.Done():
			return stage, "generation_timeout", trips
		case gen := <-generations:
			if gen.Number != count {
				return stage, "unexpected_generation", trips
			}
			if err := externalEcho(ctx, app, gen.Control.TunnelIP, peer); err != nil {
				return stage, "echo_failed", trips
			}
		}
		trips++
		if count == 1 {
			stage = "reconnect"
			if err := first.Close(); err != nil {
				return stage, "transport_close_failed", trips
			}
		}
	}
	return "verified", "", trips
}

func externalEcho(ctx context.Context, app transport.PacketConn, source, peer netip.Addr) error {
	if !source.Is4() {
		return errors.New("missing assigned IPv4 address")
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	src, dst := source.As4(), peer.As4()
	packet := make([]byte, 20+8+16)
	packet[0], packet[8], packet[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20], 0))
	packet[20] = 8
	rand.Read(packet[24:])
	binary.BigEndian.PutUint16(packet[22:24], checksum(packet[20:], 0))
	if err := app.WritePacket(ctx, packet); err != nil {
		return err
	}

	buffer := make([]byte, transport.DefaultPacketSize)
	for {
		n, err := app.ReadPacket(ctx, buffer)
		if err != nil {
			return err
		}
		if n < len(packet) || buffer[0]>>4 != 4 || buffer[9] != 1 ||
			!bytes.Equal(buffer[12:16], dst[:]) || !bytes.Equal(buffer[16:20], src[:]) {
			continue
		}
		offset := int(buffer[0]&0xf) * 4
		if offset >= 20 && n == offset+24 && buffer[offset] == 0 && buffer[offset+1] == 0 &&
			checksum(buffer[offset:n], 0) == 0 && bytes.Equal(buffer[offset+4:n], packet[24:]) {
			return nil
		}
	}
}
