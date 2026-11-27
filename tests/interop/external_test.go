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
	Profile       []profile.CapabilityEntry `json:"profile,omitempty"`
	Warnings      []profile.CapabilityEntry `json:"warnings,omitempty"`
	Stage         string                    `json:"stage"`
	Code          string                    `json:"code,omitempty"`
	Directive     string                    `json:"directive,omitempty"`
	Line          int                       `json:"line,omitempty"`
	Transport     string                    `json:"transport,omitempty"`
	Control       string                    `json:"control,omitempty"`
	Credentials   bool                      `json:"password_auth"`
	Identity      bool                      `json:"client_certificate"`
	TLS           string                    `json:"tls,omitempty"`
	AEAD          string                    `json:"aead,omitempty"`
	Derivation    client.KeyDerivation      `json:"derivation,omitempty"`
	DataFormat    string                    `json:"data_format,omitempty"`
	RoundTrips    int                       `json:"synthetic_round_trips"`
	Rekeys        int                       `json:"verified_rekeys,omitempty"`
	Attempts      []externalAttempt         `json:"attempts,omitempty"`
	Generations   []externalGeneration      `json:"generations,omitempty"`
	RekeyAttempts []client.RekeyReport      `json:"rekey_attempts,omitempty"`
}

type externalAttempt struct {
	Stage         client.AttemptStage `json:"stage"`
	Phase         client.AttemptPhase `json:"phase"`
	PhaseDuration time.Duration       `json:"phase_duration_ns"`
	PhaseSteps    uint8               `json:"phase_steps,omitempty"`
	Code          client.ErrorCode    `json:"code,omitempty"`
	RetryReason   client.ErrorCode    `json:"retry_reason,omitempty"`
}

type externalGeneration struct {
	Generation      uint64 `json:"generation"`
	PacketsSent     uint64 `json:"packets_sent"`
	PacketsReceived uint64 `json:"packets_received"`
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
	t.Setenv("OVPN_EXTERNAL_REKEY", "0")
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
			credentials, err := profile.ReadCredentialsFile(path)
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
	return probeExternalProfileWithDialer(ctx, name, transport.SocketDialer{})
}

func probeExternalProfileWithDialer(ctx context.Context, name string, dialer transport.Dialer) (result externalResult) {
	result = externalResult{Stage: "input"}
	file, err := openExternalFile(name)
	if err != nil {
		result.Code = "profile_unavailable"
		return result
	}
	defer file.Close()
	options := profile.Options{
		AllowPasswordOnly:   os.Getenv("OVPN_EXTERNAL_PASSWORD_ONLY") == "1",
		ProtonVPNServerName: os.Getenv("OVPN_EXTERNAL_PROTON_SERVER_NAME"),
		ProtonVPNVerifyIP:   os.Getenv("OVPN_EXTERNAL_PROTON_VERIFY_IP") == "1",
		ExpressVPNManual:    os.Getenv("OVPN_EXTERNAL_EXPRESSVPN") == "1",
		AccessServerName:    os.Getenv("OVPN_EXTERNAL_ACCESS_SERVER_NAME"),
	}
	report, _ := profile.InspectWithOptions(file, options)
	result.Profile = report.Entries
	if _, err := file.Seek(0, 0); err != nil {
		result.Code = "profile_unavailable"
		return result
	}
	if path := os.Getenv("OVPN_EXTERNAL_AUTH_FILE"); path != "" {
		options.Credentials, err = profile.ReadCredentialsFile(path)
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
	rekeyCount := 0
	if os.Getenv("OVPN_EXTERNAL_REKEY") == "1" {
		rekeyCount = 1
		if value := os.Getenv("OVPN_EXTERNAL_REKEY_COUNT"); value != "" {
			rekeyCount, err = strconv.Atoi(value)
			if err != nil || rekeyCount < 1 || rekeyCount > 10 {
				result.Code = "invalid_rekey_count"
				return result
			}
		}
		interval := 2
		if value := os.Getenv("OVPN_EXTERNAL_REKEY_SECONDS"); value != "" {
			interval, err = strconv.Atoi(value)
			if err != nil || interval < 1 || interval > 20 {
				result.Code = "invalid_rekey_interval"
				return result
			}
		}
		cfg.DisableTimedRekey, cfg.RekeyInterval = false, time.Duration(interval)*time.Second
	}

	peer := netip.Addr{}
	echoTarget := os.Getenv("OVPN_EXTERNAL_ECHO")
	if echoTarget != "" && echoTarget != "gateway" {
		value := echoTarget
		peer, err = netip.ParseAddr(value)
		if err != nil || peer.Is4In6() || peer.Zone() != "" || !peer.IsGlobalUnicast() {
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
		link, err := dialer.DialPacket(ctx, network, address)
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
	defer func() {
		c.Close()
		result.RekeyAttempts = c.RekeyReports()
		for _, a := range c.AttemptReports(0) {
			result.Attempts = append(result.Attempts, externalAttempt{
				Stage: a.Stage, Phase: a.Phase, PhaseDuration: a.PhaseDuration, PhaseSteps: a.PhaseSteps, Code: a.Code, RetryReason: a.RetryReason,
			})
		}
		for _, g := range c.GenerationReports(0) {
			result.Generations = append(result.Generations, externalGeneration{
				Generation: g.Generation, PacketsSent: g.PacketsSent, PacketsReceived: g.PacketsReceived,
			})
		}
	}()
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
	result.Derivation, result.DataFormat = info.KeyDerivation, info.DataFormat
	if peer.IsValid() || echoTarget == "gateway" {
		budget := max(35*time.Second, time.Duration(rekeyCount)*(cfg.RekeyInterval+6*time.Second)+5*time.Second)
		result.Stage, result.Code, result.RoundTrips = probeExternalData(ctx, c, first, peer, rekeyCount, budget)
		if rekeyCount != 0 {
			result.Rekeys = max(0, result.RoundTrips-1)
		}
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

// When explicitly given a test-owned IPv4 or IPv6 echo target, exercise data on both
// sides of a transport interruption without creating an OS tunnel or routes.
// An invalid peer requests the IPv4 gateway of each authenticated generation.
func probeExternalData(ctx context.Context, c *client.Client, first transport.PacketConn, peer netip.Addr, rekeyCount int, budget time.Duration) (stage, code string, trips int) {
	ctx, cancel := context.WithTimeout(ctx, budget)
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
		var target netip.Addr
		select {
		case err := <-done:
			return stage, externalError(err), trips
		case <-ctx.Done():
			return stage, "generation_timeout", trips
		case gen := <-generations:
			if gen.Number != count {
				return stage, "unexpected_generation", trips
			}
			target = peer
			if !target.IsValid() {
				target = gen.Control.Tunnel.GatewayIPv4
				if !target.Is4() {
					return stage, "missing_ipv4_gateway", trips
				}
			}
			if err := externalControlEcho(ctx, app, gen.Control, target); err != nil {
				return stage, "echo_failed", trips
			}
		}
		trips++
		if count == 1 {
			if rekeyCount != 0 {
				if current, ok := c.ControlInfo(); !ok || current.KeyID != 0 {
					return "rekey", "initial_key_not_verified", trips
				}
				return probeExternalRekey(ctx, c, app, target, done, rekeyCount)
			}
			stage = "reconnect"
			if err := first.Close(); err != nil {
				return stage, "transport_close_failed", trips
			}
		}
	}
	return "verified", "", trips
}

func probeExternalRekey(ctx context.Context, c *client.Client, app transport.PacketConn, peer netip.Addr, done <-chan error, count int) (string, string, int) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	trips := 1
	var previous uint8
	for trips <= count {
		select {
		case err := <-done:
			return "rekey", externalError(err), trips
		case <-ctx.Done():
			return "rekey", "generation_timeout", trips
		case <-ticker.C:
			if c.Stats().Connections != 1 {
				return "rekey", "replaced_connection", trips
			}
			info, ok := c.ControlInfo()
			if !ok || info.KeyID == previous {
				continue
			}
			if info.KeyID != previous%7+1 {
				return "rekey", "unexpected_key_id", trips
			}
			if err := externalControlEcho(ctx, app, info, peer); err != nil {
				return "rekey", "echo_failed", trips
			}
			if c.Stats().Connections != 1 {
				return "rekey", "replaced_connection", trips
			}
			if after, ok := c.ControlInfo(); !ok || after.KeyID != info.KeyID {
				return "rekey", "echo_spanned_key_change", trips
			}
			previous = info.KeyID
			trips++
		}
	}
	return "rekey_verified", "", trips
}

func externalEcho(ctx context.Context, app transport.PacketConn, source, peer netip.Addr) error {
	if !source.Is4() {
		return errors.New("missing assigned IPv4 address")
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	src, dst := source.As4(), peer.As4()
	// Match the payload size of the Community reference ICMP probe.
	const payloadSize = 56
	packet := make([]byte, 20+8+payloadSize)
	packet[0], packet[8], packet[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20], 0))
	packet[20] = 8
	rand.Read(packet[24:])
	binary.BigEndian.PutUint16(packet[22:24], checksum(packet[20:], 0))
	buffer := make([]byte, transport.DefaultPacketSize)
	for ctx.Err() == nil {
		round, stop := context.WithTimeout(ctx, 300*time.Millisecond)
		err := app.WritePacket(round, packet)
		if err == nil {
			err = readExternalEcho(round, app, buffer, packet, src, dst)
		}
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return ctx.Err()
}

func readExternalEcho(ctx context.Context, app transport.PacketConn, buffer, packet []byte, src, dst [4]byte) error {
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
		if offset >= 20 && n == offset+len(packet)-20 && buffer[offset] == 0 && buffer[offset+1] == 0 &&
			checksum(buffer[offset:n], 0) == 0 && bytes.Equal(buffer[offset+4:n], packet[24:]) {
			return nil
		}
	}
}
