//go:build linux

package interop_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

type loadResolver func(context.Context, string, string) ([]netip.Addr, error)

func (resolve loadResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return resolve(ctx, network, host)
}

func TestConcurrentReconnectAdmission(t *testing.T) {
	if os.Getenv("OPENVPN_RECONNECT_LOAD") != "1" {
		t.Skip("explicit opt-in for the isolated reconnect burst")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("reconnect workload requires a dedicated network namespace")
	}
	sessions := 64
	if value := os.Getenv("OPENVPN_RECONNECT_SESSIONS"); value != "" {
		sessions, err = strconv.Atoi(value)
		if err != nil || sessions < 2 || sessions > 1000 {
			t.Fatal("invalid OPENVPN_RECONNECT_SESSIONS")
		}
	}
	const concurrency = 8
	forceRekey := os.Getenv("OPENVPN_RECONNECT_REKEY") == "1"
	var failedStage client.AttemptStage
	mode := os.Getenv("OPENVPN_RECONNECT_FAILURE")
	switch mode {
	case "", "authentication", "peer-rekey":
	case "resolve":
		failedStage = client.StageResolve
	case "dial":
		failedStage = client.StageDial
	default:
		t.Fatal("invalid OPENVPN_RECONNECT_FAILURE")
	}
	if forceRekey && mode == "peer-rekey" {
		t.Fatal("choose either peer or client rekey")
	}
	passwordAuth := mode == "authentication"
	renegotiate := "0"
	if mode == "peer-rekey" {
		renegotiate = "5"
	}
	limiter, err := client.NewHandshakeLimiter(concurrency, sessions)
	if err != nil {
		t.Fatal(err)
	}
	pki := testkit.NewPKI(t)
	f := makePKIFixture(t, interopPeer(t), pki)
	port := localPort(t, "tcp")
	startPeer := func() func() {
		args := serverArgs(port, "tcp", "tls", passwordAuth, "--dev", dataDevice, "--duplicate-cn", "--keepalive", "1", "4", "--verb", "1",
			"--max-clients", strconv.Itoa(sessions), "--tcp-nodelay", "--reneg-sec", renegotiate)
		for i, flag := range args {
			if flag == "--server" {
				args[i+2] = "255.255.252.0"
				break
			}
		}
		stop, _ := f.launchArgs(t, args)
		configureTestLink(t, "10.49.0.1/22")
		return stop
	}
	stop := startPeer()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	clients := make([]loadTunnel, sessions)
	var running sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		for _, connection := range clients {
			if connection.client != nil {
				connection.client.Close()
				connection.app.Close()
			}
		}
		running.Wait()
		if stats := limiter.Stats(); stats.InFlight != 0 || stats.Waiting != 0 || stats.Rejected != 0 || stats.PeakInFlight > concurrency {
			t.Errorf("invalid admission cleanup: %+v", stats)
		}
	})
	ready := make(chan error, sessions)
	runResults := make(chan error, sessions)
	var outage atomic.Bool
	waitTimeout := func(ctx context.Context) error {
		timeout, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		<-timeout.Done()
		return timeout.Err()
	}
	for i := range clients {
		cfg := f.config(pki, "tcp", "tls", port, passwordAuth)
		cfg.HandshakeLimiter = limiter
		cfg.ConnectTimeout = 30 * time.Second
		switch failedStage {
		case client.StageResolve:
			cfg.Endpoints[0].Host = testkit.TestServerName
			cfg.Resolver = loadResolver(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
				if outage.Load() {
					return nil, waitTimeout(ctx)
				}
				return []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})}, nil
			})
		case client.StageDial:
			cfg.Dialer = testkit.DialerFunc(func(ctx context.Context, network, address string) (transport.PacketConn, error) {
				if outage.Load() {
					return nil, waitTimeout(ctx)
				}
				return (transport.SocketDialer{}).DialPacket(ctx, network, address)
			})
		}
		if forceRekey {
			cfg.RekeyInterval = 5 * time.Second
			cfg.HandshakeTimeout = 30 * time.Second
		}
		cfg.Retry = client.RetryPolicy{MaxAttempts: client.UnlimitedAttempts, InitialBackoff: 100 * time.Millisecond, MaxBackoff: time.Second}
		c, err := client.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		device, app := testkit.PacketPipe(8, transport.DefaultPacketSize)
		clients[i] = loadTunnel{client: c, app: app}
		running.Go(func() {
			defer device.Close()
			err := c.Connect(ctx)
			ready <- err
			if err == nil {
				runResults <- c.Run(ctx, device)
			}
		})
	}
	for range clients {
		if err := <-ready; err != nil {
			t.Fatalf("admitted connection failed: %v", err)
		}
	}
	outage.Store(true)
	stop()
	awaitReconnectCondition(t, ctx, clients, func(stats client.Stats) bool { return stats.Disconnects >= 1 })
	if failedStage != "" {
		awaitReconnectCondition(t, ctx, clients, func(stats client.Stats) bool { return stats.AttemptFailures > 0 })
		for _, connection := range clients {
			for _, report := range connection.client.AttemptReports(1) {
				if report.Code != "" && report.Stage != failedStage {
					t.Fatalf("outage ended in %s, want %s", report.Stage, failedStage)
				}
			}
		}
	}
	if passwordAuth {
		if err := os.WriteFile(filepath.Join(f.dir, "verify-user"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cpu := processLoadCPU(t)
	started := time.Now()
	startPeer()
	outage.Store(false)
	if passwordAuth {
		for range sessions {
			select {
			case err := <-runResults:
				var failure *client.Error
				if !errors.As(err, &failure) || failure.Code != client.CodeAuthentication {
					t.Fatalf("verified peer rejection was not terminal: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("authentication failures did not stop all reconnects")
			}
		}
		for _, connection := range clients {
			reports := connection.client.AttemptReports(1)
			var denials int
			for _, report := range reports {
				if report.Stage == client.StageAuthentication {
					denials++
				}
			}
			if len(reports) == 0 || denials != 1 || reports[len(reports)-1].Code != client.CodeAuthentication ||
				connection.client.Stats().Connections != 1 {
				t.Fatalf("unexpected terminal authentication sequence: %+v", reports)
			}
		}
		t.Logf("terminal_rejections=%d elapsed=%s driver_cpu_seconds=%.3f admission=%+v",
			sessions, time.Since(started), processLoadCPU(t)-cpu, limiter.Stats())
		return
	}
	awaitReconnectCondition(t, ctx, clients, func(stats client.Stats) bool { return stats.Connections >= 2 && stats.State == client.StateConnected })
	recovery := make([]time.Duration, 0, sessions)
	var attempts, failures uint64
	for _, connection := range clients {
		stats := connection.client.Stats()
		recovery = append(recovery, stats.ConnectedSince.Sub(started))
		attempts += stats.Attempts
		failures += stats.AttemptFailures
	}
	sort.Slice(recovery, func(i, j int) bool { return recovery[i] < recovery[j] })
	var sample loadSample
	readLoadResources(t, &sample)
	t.Logf("recovered=%d total_p50=%s p95=%s p99=%s attempts=%d failures=%d average_recovery_per_s=%.1f driver_cpu_seconds=%.3f rss_bytes=%d heap_bytes=%d fds=%d admission=%+v",
		sessions, recovery[sessions/2], recovery[(95*sessions+99)/100-1], recovery[(99*sessions+99)/100-1], attempts, failures,
		float64(sessions)/time.Since(started).Seconds(), processLoadCPU(t)-cpu, sample.RSS, sample.Heap, sample.FDs, limiter.Stats())
	if forceRekey || mode == "peer-rekey" {
		for _, connection := range clients {
			ticker := time.NewTicker(50 * time.Millisecond)
		waitRekey:
			for {
				for _, rekey := range connection.client.RekeyReports() {
					if rekey.Generation == 2 && rekey.Code == "" && rekey.PeerInitiated == (mode == "peer-rekey") {
						break waitRekey
					}
				}
				select {
				case <-ctx.Done():
					ticker.Stop()
					t.Fatal("a recovered connection did not rekey")
				case <-ticker.C:
				}
			}
			ticker.Stop()
		}
		t.Logf("rekeyed=%d admission=%+v", sessions, limiter.Stats())
	}
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 49, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	for _, connection := range []loadTunnel{clients[0], clients[sessions-1]} {
		info, ok := connection.client.ControlInfo()
		if !ok {
			t.Fatal("recovered connection missing authenticated configuration")
		}
		roundtrip(t, connection.app, echo, info.TunnelIP.AsSlice(), []byte("after shared endpoint recovery"))
	}
}

func awaitReconnectCondition(t *testing.T, ctx context.Context, clients []loadTunnel, ready func(client.Stats) bool) {
	t.Helper()
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	for {
		count := 0
		for _, connection := range clients {
			if ready(connection.client.Stats()) {
				count++
			}
		}
		if count == len(clients) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("only %d/%d sessions reached the expected lifecycle state", count, len(clients))
		case <-timer.C:
		}
	}
}
