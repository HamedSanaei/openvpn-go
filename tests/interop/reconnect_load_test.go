//go:build linux

package interop_test

import (
	"context"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
)

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
	limiter, err := client.NewHandshakeLimiter(concurrency, sessions)
	if err != nil {
		t.Fatal(err)
	}
	pki := testkit.NewPKI(t)
	f := makePKIFixture(t, interopPeer(t), pki)
	port := localPort(t, "tcp")
	startPeer := func() func() {
		args := serverArgs(port, "tcp", "tls", false, "--dev", dataDevice, "--duplicate-cn", "--keepalive", "1", "4", "--verb", "1",
			"--max-clients", strconv.Itoa(sessions), "--tcp-nodelay", "--reneg-sec", "0")
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
	for i := range clients {
		cfg := f.config(pki, "tcp", "tls", port, false)
		cfg.HandshakeLimiter = limiter
		cfg.ConnectTimeout = 30 * time.Second
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
				c.Run(ctx, device)
			}
		})
	}
	for range clients {
		if err := <-ready; err != nil {
			t.Fatalf("admitted connection failed: %v", err)
		}
	}
	stop()
	awaitReconnectCondition(t, ctx, clients, func(stats client.Stats) bool { return stats.Disconnects >= 1 })
	cpu := processLoadCPU(t)
	started := time.Now()
	startPeer()
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
	if forceRekey {
		for _, connection := range clients {
			ticker := time.NewTicker(50 * time.Millisecond)
		waitRekey:
			for {
				for _, rekey := range connection.client.RekeyReports() {
					if rekey.Generation == 2 && rekey.Code == "" {
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
