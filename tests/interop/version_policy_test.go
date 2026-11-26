//go:build linux

package interop_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestCommunity27EpochPolicy(t *testing.T) {
	if os.Getenv("OPENVPN_INTEROP_VERSION") != "2.7.9" {
		t.Skip("requires the pinned OpenVPN 2.7.9 reference")
	}
	binary := interopPeer(t)
	pki := testkit.NewPKI(t)
	f := makeFixture(t, binary, pki)
	t.Run("authenticated_epoch_push_is_rejected", func(t *testing.T) {
		port := localPort(t, "tcp")
		stop, logPath := f.launchArgs(t, serverArgs(port, "tcp", "tls", false, "--push", "protocol-flags tls-ekm aead-epoch"))
		rejectProtocol(t, f.config(pki, "tcp", "tls", port, false))
		stop()
		raw, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if push := serverPush(string(raw)); !strings.Contains(push, "protocol-flags tls-ekm aead-epoch") {
			t.Fatalf("the reference did not send the epoch flag: %q", push)
		} else {
			t.Log(push)
		}
	})
	t.Run("community_peers_select_epoch", func(t *testing.T) {
		port := f.start(t, "tcp", "tls", false)
		config := fmt.Sprintf("client\ndev tun\nproto tcp4-client\nremote 127.0.0.1 %d\n"+
			"remote-cert-tls server\nverify-x509-name %s name\n", port, testkit.TestServerName) + profilePKI(pki)
		file := filepath.Join(t.TempDir(), "community.ovpn")
		if err := os.WriteFile(file, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		log, err := os.CreateTemp(t.TempDir(), "community-log-")
		if err != nil {
			t.Fatal(err)
		}
		defer log.Close()
		cmd := exec.CommandContext(ctx, binary, "--config", file, "--disable-dco", "--ifconfig-noexec", "--route-noexec", "--verb", "4")
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { cancel(); cmd.Wait() }()
		for deadline := time.Now().Add(4 * time.Second); time.Now().Before(deadline); {
			raw, err := os.ReadFile(log.Name())
			if err != nil {
				t.Fatal(err)
			}
			output := string(raw)
			if strings.Contains(output, "Initialization Sequence Completed") {
				for line := range strings.SplitSeq(output, "\n") {
					if strings.Contains(line, "PUSH: Received control message: 'PUSH_REPLY") && strings.Contains(line, "aead-epoch") {
						t.Log(line)
						return
					}
				}
				t.Fatalf("the reference clients connected without selecting epoch:\n%s", output)
			}
			time.Sleep(10 * time.Millisecond)
		}
		raw, _ := os.ReadFile(log.Name())
		t.Fatalf("the reference clients did not connect:\n%s", raw)
	})
}

func TestLegacyCommunityAEADPolicy(t *testing.T) {
	binary, version := os.Getenv("OPENVPN_LEGACY_BIN"), os.Getenv("OPENVPN_LEGACY_VERSION")
	if binary == "" && version == "" {
		t.Skip("requires the pinned OpenVPN 2.4.12 or 2.5.11 reference")
	}
	out, err := exec.CommandContext(t.Context(), binary, "--version").Output()
	if !versionExitOK(err) || (version != "2.4.12" && version != "2.5.11") ||
		!strings.HasPrefix(string(out), "OpenVPN "+version+" ") {
		t.Fatalf("unexpected legacy peer version output: %v\n%s", err, out)
	}

	pki := testkit.NewPKI(t)
	f := makePKIFixture(t, binary, pki)
	port := localPort(t, "tcp")
	args := []string{
		"--dev", "tun", "--proto", "tcp4-server", "--local", "127.0.0.1", "--port", strconv.Itoa(int(port)),
		"--server", "10.49.0.0", "255.255.255.0", "--topology", "subnet", "--ifconfig-noexec", "--route-noexec",
		"--ca", "ca.pem", "--cert", "server.pem", "--key", "server.key", "--dh", "none",
		"--tls-version-min", "1.2", "--tls-version-max", "1.2", "--cipher", "AES-256-GCM", "--verb", "4",
	}
	const aead = "AES-256-GCM:AES-128-GCM"
	if version == "2.4.12" {
		args = append(args, "--ncp-ciphers", aead)
	} else {
		args = append(args, "--data-ciphers", aead)
	}
	stop, logPath := f.launchArgs(t, args)
	rejectProtocol(t, f.config(pki, "tcp", "tls", port, false))
	stop()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Control Channel: TLSv1.2") {
		t.Fatal("legacy reference did not establish the authenticated TLS 1.2 control channel")
	}
	push := serverPush(string(raw))
	if push == "" {
		t.Fatal("legacy reference did not send a PUSH_REPLY")
	}
	if strings.Contains(push, "tls-ekm") || strings.Contains(push, "CBC") ||
		strings.Contains(push, "comp-lzo") || strings.Contains(push, ",compress") {
		t.Fatalf("unexpected legacy negotiation: %s", push)
	}
	if version == "2.4.12" && strings.Contains(push, ",cipher ") {
		t.Fatalf("2.4 unexpectedly negotiated a cipher without IV_NCP: %s", push)
	}
	if version == "2.5.11" && !strings.Contains(push, ",cipher AES-256-GCM") {
		t.Fatalf("2.5 did not select AES-256-GCM: %s", push)
	}
	t.Log(push)
}

func serverPush(log string) string {
	for line := range strings.SplitSeq(log, "\n") {
		if strings.Contains(line, "SENT CONTROL") && strings.Contains(line, "PUSH_REPLY") {
			return line
		}
	}
	return ""
}

func rejectProtocol(t *testing.T, cfg client.Config) {
	t.Helper()
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.Connect(t.Context())
	var typed *client.Error
	if !errors.As(err, &typed) || typed.Code != client.CodeProtocol {
		t.Fatalf("Connect = %v; want %s", err, client.CodeProtocol)
	}
	if _, ok := c.ControlInfo(); ok {
		t.Fatal("rejected negotiation published control information")
	}
	if _, ok := c.ActiveEndpoint(); ok {
		t.Fatal("rejected negotiation published an active endpoint")
	}
}

// OpenVPN 2.4 and 2.5 can exit with status 1 after printing --version.
func versionExitOK(err error) bool {
	var exit *exec.ExitError
	return err == nil || errors.As(err, &exit) && exit.ExitCode() == 1
}
