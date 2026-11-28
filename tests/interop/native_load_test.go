//go:build linux

package interop_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/testkit"
	"github.com/hamedsanaei/openvpn-go/transport"
	"golang.org/x/sys/unix"
)

type loadSettings struct {
	network, workload                      string
	sessions, windows, batch, restartEvery int
	duration, warmup, rekey, pause         time.Duration
	managed                                bool
}

type loadSample struct {
	Window              int           `json:"window"`
	Network             string        `json:"network"`
	Workload            string        `json:"workload"`
	Sessions            int           `json:"sessions"`
	Batch               int           `json:"window_packets"`
	ConfiguredSeconds   int           `json:"configured_seconds"`
	WarmupSeconds       int           `json:"warmup_seconds"`
	ExpectedWindows     int           `json:"expected_windows"`
	PauseUS             int           `json:"pause_us"`
	RestartEvery        int           `json:"restart_every"`
	RekeySeconds        int           `json:"rekey_seconds"`
	Managed             bool          `json:"managed,omitempty"`
	Seconds             float64       `json:"seconds"`
	Sent                uint64        `json:"sent"`
	Received            uint64        `json:"received"`
	PayloadBytes        uint64        `json:"payload_bytes"`
	ReceivedBySize      [3]uint64     `json:"received_by_size"`
	P50                 time.Duration `json:"p50_ns"`
	P95                 time.Duration `json:"p95_ns"`
	P99                 time.Duration `json:"p99_ns"`
	CPUSeconds          float64       `json:"driver_cpu_seconds"`
	Allocations         uint64        `json:"driver_allocations"`
	AllocatedBytes      uint64        `json:"driver_allocated_bytes"`
	Heap                uint64        `json:"heap_bytes"`
	Stack               uint64        `json:"stack_bytes"`
	RSS                 uint64        `json:"rss_bytes"`
	GC                  uint32        `json:"gc_cycles"`
	GCPause             uint64        `json:"gc_pause_ns"`
	Goroutines          int           `json:"goroutines"`
	FDs                 int           `json:"fds"`
	QueueDrops          uint64        `json:"queue_drops"`
	QueueHighWater      uint64        `json:"queue_high_water"`
	Connections         uint64        `json:"connections"`
	Rekeys              uint64        `json:"recent_rekeys"`
	SilentTunnels       int           `json:"silent_tunnels"`
	FailedTunnels       int           `json:"failed_tunnels"`
	MinTunnelEchoes     uint64        `json:"min_tunnel_echoes"`
	MaxTunnelEchoes     uint64        `json:"max_tunnel_echoes"`
	RecoveryP50         time.Duration `json:"recovery_p50_ns,omitempty"`
	RecoveryP95         time.Duration `json:"recovery_p95_ns,omitempty"`
	RecoveryP99         time.Duration `json:"recovery_p99_ns,omitempty"`
	KernelUDPErrors     uint64        `json:"kernel_udp_input_errors"`
	KernelUDPReadDrops  uint64        `json:"kernel_udp_receive_buffer_errors"`
	KernelUDPWriteDrops uint64        `json:"kernel_udp_send_buffer_errors"`
}

const loadLatencyBuckets = 384

type loadHistogram [loadLatencyBuckets]uint64

var loadLatencyBounds = func() [loadLatencyBuckets]time.Duration {
	var bounds [loadLatencyBuckets]time.Duration
	bound := time.Microsecond
	for i := range bounds {
		bounds[i] = bound
		bound += bound / 16
	}
	return bounds
}()

func (h *loadHistogram) observe(d time.Duration) {
	i := sort.Search(len(h), func(i int) bool { return d <= loadLatencyBounds[i] })
	h[min(i, len(h)-1)]++
}

func (h *loadHistogram) percentile(total, percent uint64) time.Duration {
	target := (total*percent + 99) / 100
	var count uint64
	for i, n := range h {
		count += n
		if count >= target {
			return loadLatencyBounds[i]
		}
	}
	return 0
}

type loadTunnel struct {
	client         *client.Client
	app            transport.PacketConn
	managedAddress func() netip.Addr
	managedStatus  func() (client.Stats, bool)
}

func (t loadTunnel) address() netip.Addr {
	if t.managedAddress != nil {
		return t.managedAddress()
	}
	info, _ := t.client.ControlInfo()
	return info.TunnelIP
}

// Older baselines can run the overlaid direct-client harness without importing
// manager APIs added after those revisions.
var startManagedLoad func(*testing.T, []loadTunnel) func(int, client.Config)

var waitManagedLoad func(*testing.T, []loadTunnel)

type loadTraffic struct {
	sent, received, payload uint64
	receivedBySize          [3]uint64
	latency                 loadHistogram
	failed                  bool
	firstResponse           time.Time
}

// TestNativeLoad uses only loopback and an isolated peer. It writes one
// measurement per window so long runs leave usable samples on interruption.
func TestNativeLoad(t *testing.T) {
	if os.Getenv("OPENVPN_NATIVE_LOAD") != "1" {
		t.Skip("explicit opt-in for isolated native load testing")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Flags&net.FlagLoopback == 0 {
		t.Fatal("load test requires a dedicated network namespace with only loopback")
	}
	settings := loadConfig(t)
	var initial loadSample
	readLoadResources(t, &initial)
	outputPath := os.Getenv("OPENVPN_LOAD_JSON")
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("could not create private load report")
	}
	defer output.Close()
	encoder := json.NewEncoder(output)
	t.Cleanup(func() {
		runtime.GC()
		var final loadSample
		readLoadResources(t, &final)
		raw, err := json.Marshal(map[string]map[string]uint64{
			"initial": {"heap_bytes": initial.Heap, "stack_bytes": initial.Stack, "rss_bytes": initial.RSS,
				"fds": uint64(initial.FDs), "goroutines": uint64(initial.Goroutines)},
			"after_cleanup": {"heap_bytes": final.Heap, "stack_bytes": final.Stack, "rss_bytes": final.RSS,
				"fds": uint64(final.FDs), "goroutines": uint64(final.Goroutines)},
		})
		if err != nil || os.WriteFile(outputPath+".cleanup.json", raw, 0600) != nil {
			t.Error("could not write cleanup measurements")
		}
	})
	binaryPath := interopPeer(t)
	pki := nativeLoadPKI(t, settings)
	f := makePKIFixture(t, binaryPath, pki)
	probe := os.Getenv("OPENVPN_LOAD_CONSTRAINTS")
	if probe != "" {
		f.binary = os.Getenv("OPENVPN_LOAD_PEER_WRAPPER")
	}
	var constraints []byte
	checkConstraints := func() {
		if probe == "" {
			return
		}
		peerPID, err := os.ReadFile(outputPath + ".peer-pid")
		if err != nil {
			t.Fatal("cannot identify native-load peer")
		}
		report, err := exec.CommandContext(t.Context(), "python3", probe,
			strconv.Itoa(os.Getpid()), strings.TrimSpace(string(peerPID))).Output()
		if err != nil || !json.Valid(report) {
			t.Fatal("cannot verify native-load participant scheduling constraints")
		}
		if constraints != nil && !bytes.Equal(report, constraints) {
			t.Fatal("native-load participant scheduling changed within the run")
		}
		constraints = report
	}
	port := localPort(t, settings.network)
	startPeer := func() func() {
		args := serverArgs(port, settings.network, "tls", false, "--dev", "tun-load", "--duplicate-cn",
			"--max-clients", strconv.Itoa(settings.sessions), "--keepalive", "1", "4", "--verb", "1")
		if settings.network == "tcp" {
			args = append(args, "--tcp-nodelay")
		}
		for i, value := range args {
			if value == "--server" {
				args[i+2] = "255.255.252.0"
				break
			}
		}
		stop, _ := f.launchArgs(t, args)
		configureLink(t, "tun-load", "10.49.0.1/22")
		return stop
	}
	stop := startPeer()
	checkConstraints()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 49, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	echoDone := make(chan error, 1)
	go func() {
		var b [1400]byte
		for {
			n, from, err := echo.ReadFromUDPAddrPort(b[:])
			if err == nil {
				_, err = echo.WriteToUDPAddrPort(b[:n], from)
			}
			if err != nil {
				echoDone <- err
				return
			}
		}
	}()
	defer func() { echo.Close(); <-echoDone }()

	tunnels := make([]loadTunnel, settings.sessions)
	start := func(index int, cfg client.Config) {
		tunnels[index].client, tunnels[index].app = connectData(t, cfg)
	}
	if settings.managed {
		if startManagedLoad == nil {
			t.Fatal("this revision does not support the managed load workload")
		}
		start = startManagedLoad(t, tunnels)
	}
	for i := range tunnels {
		cfg := f.config(pki, settings.network, "tls", port, false)
		cfg.RekeyInterval = settings.rekey
		cfg.Retry = client.RetryPolicy{MaxAttempts: client.UnlimitedAttempts, InitialBackoff: 100 * time.Millisecond, MaxBackoff: time.Second}
		start(i, cfg)
	}
	if settings.managed {
		waitManagedLoad(t, tunnels)
	}
	t.Logf("workload ready: network=%s tunnels=%d windows=%d", settings.network, settings.sessions, settings.windows)
	if settings.warmup != 0 {
		runLoadWindow(t, settings, tunnels, echo.LocalAddr().(*net.UDPAddr).AddrPort(), settings.warmup, 0, time.Time{})
	}
	for i := 1; i <= settings.windows; i++ {
		var restarting time.Time
		if settings.restartEvery != 0 && i > 1 && (i-1)%settings.restartEvery == 0 {
			stop()
			time.Sleep(5 * time.Second)
			restarting = time.Now()
			stop = startPeer()
		}
		sample := runLoadWindow(t, settings, tunnels, echo.LocalAddr().(*net.UDPAddr).AddrPort(), settings.duration, i, restarting)
		checkConstraints()
		if err := encoder.Encode(sample); err != nil {
			t.Fatal(err)
		}
		if sample.Received == 0 || sample.Received > sample.Sent || sample.P99 == 0 || sample.FailedTunnels != 0 {
			t.Fatal("invalid or empty load sample")
		}
	}
	if constraints != nil && os.WriteFile(outputPath+".constraints.json", constraints, 0600) != nil {
		t.Fatal("could not save native-load scheduling constraints")
	}
}

// Kept optional when this harness is overlaid on an older comparison revision.
var longLoadPKI func(*testing.T, time.Duration) testkit.PKI

func nativeLoadPKI(t *testing.T, settings loadSettings) testkit.PKI {
	t.Helper()
	planned := time.Duration(settings.windows)*settings.duration + settings.warmup
	if settings.restartEvery != 0 {
		planned += time.Duration((settings.windows-1)/settings.restartEvery) * 10 * time.Second
	}
	if planned <= 30*time.Minute {
		return testkit.NewPKI(t)
	}
	if longLoadPKI == nil {
		t.Fatal("this revision does not support the synthetic certificate lifetime required for a long run")
	}
	return longLoadPKI(t, planned+2*time.Hour)
}

func loadConfig(t *testing.T) loadSettings {
	t.Helper()
	integer := func(name string, fallback, minValue, maxValue int) int {
		if value := os.Getenv("OPENVPN_LOAD_" + name); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < minValue || n > maxValue {
				t.Fatalf("invalid OPENVPN_LOAD_%s", name)
			}
			return n
		}
		return fallback
	}
	settings := loadSettings{
		sessions: integer("SESSIONS", 1, 1, 1000), windows: integer("WINDOWS", 3, 1, 720),
		batch: integer("BATCH", 4, 1, 8), restartEvery: integer("RESTART_EVERY", 0, 0, 720),
		duration: time.Duration(integer("SECONDS", 3, 1, 3600)) * time.Second,
		warmup:   time.Duration(integer("WARMUP", 1, 0, 600)) * time.Second,
		rekey:    time.Duration(integer("REKEY", 0, 0, 3600)) * time.Second,
		pause:    time.Duration(integer("PAUSE_US", 0, 0, 1000000)) * time.Microsecond,
		network:  os.Getenv("OPENVPN_LOAD_NETWORK"), workload: os.Getenv("OPENVPN_LOAD_PACKETS"),
		managed: integer("MANAGED", 0, 0, 1) == 1,
	}
	if settings.network == "" {
		settings.network = "udp"
	}
	if settings.workload == "" {
		settings.workload = "mixed"
	}
	if (settings.network != "tcp" && settings.network != "udp") ||
		(settings.workload != "mixed" && settings.workload != "64" && settings.workload != "256" && settings.workload != "1400") ||
		time.Duration(settings.windows)*settings.duration > 72*time.Hour {
		t.Fatal("unsupported native load settings")
	}
	return settings
}

func runLoadWindow(t *testing.T, settings loadSettings, tunnels []loadTunnel, echo netip.AddrPort, duration time.Duration, window int, restarting time.Time) loadSample {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), duration)
	defer cancel()
	traffic := make([]loadTraffic, len(tunnels))
	var workers sync.WaitGroup
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	cpu := processLoadCPU(t)
	start := time.Now()
	for i, tunnel := range tunnels {
		workers.Go(func() { loadLoop(ctx, settings, tunnel, echo, window, &traffic[i]) })
	}
	workers.Wait()
	sample := loadSample{Window: window, Network: settings.network, Workload: settings.workload, Sessions: len(tunnels),
		Managed: settings.managed, MinTunnelEchoes: ^uint64(0),
		Batch: settings.batch, ConfiguredSeconds: int(duration / time.Second), RestartEvery: settings.restartEvery,
		WarmupSeconds: int(settings.warmup / time.Second), ExpectedWindows: settings.windows,
		PauseUS:      int(settings.pause / time.Microsecond),
		RekeySeconds: int(settings.rekey / time.Second), Seconds: time.Since(start).Seconds(), CPUSeconds: processLoadCPU(t) - cpu}
	runtime.ReadMemStats(&after)
	sample.Allocations, sample.AllocatedBytes = after.Mallocs-before.Mallocs, after.TotalAlloc-before.TotalAlloc
	var histogram, recovery loadHistogram
	var recovered uint64
	for i, result := range traffic {
		sample.Sent += result.sent
		sample.Received += result.received
		sample.PayloadBytes += result.payload
		for j, count := range result.receivedBySize {
			sample.ReceivedBySize[j] += count
		}
		sample.MinTunnelEchoes = min(sample.MinTunnelEchoes, result.received)
		sample.MaxTunnelEchoes = max(sample.MaxTunnelEchoes, result.received)
		for j, count := range result.latency {
			histogram[j] += count
		}
		connection := tunnels[i]
		var stats client.Stats
		if connection.managedStatus != nil {
			var done bool
			stats, done = connection.managedStatus()
			result.failed = result.failed || done
		} else {
			stats = connection.client.Stats()
			for _, rekey := range connection.client.RekeyReports() {
				if rekey.Code == "" {
					sample.Rekeys++
				}
			}
		}
		sample.QueueDrops += stats.CiphertextQueue.Dropped + stats.InboundQueue.Dropped
		sample.QueueHighWater = max(sample.QueueHighWater, stats.CiphertextQueue.HighWater, stats.InboundQueue.HighWater)
		sample.Connections += stats.Connections
		if result.failed {
			sample.FailedTunnels++
		}
		if result.received == 0 {
			sample.SilentTunnels++
		} else if !restarting.IsZero() {
			recovery.observe(result.firstResponse.Sub(restarting))
			recovered++
		}
	}
	if sample.Received != 0 {
		sample.P50, sample.P95, sample.P99 = histogram.percentile(sample.Received, 50), histogram.percentile(sample.Received, 95), histogram.percentile(sample.Received, 99)
	}
	if recovered != 0 {
		sample.RecoveryP50, sample.RecoveryP95, sample.RecoveryP99 = recovery.percentile(recovered, 50), recovery.percentile(recovered, 95), recovery.percentile(recovered, 99)
	}
	readLoadResources(t, &sample)
	return sample
}

func readLoadResources(t *testing.T, sample *loadSample) {
	t.Helper()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	sample.Heap, sample.Stack, sample.GC, sample.GCPause = mem.HeapAlloc, mem.StackInuse, mem.NumGC, mem.PauseTotalNs
	sample.Goroutines = runtime.NumGoroutine()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	sample.FDs = len(fds) - 1 // Exclude the descriptor used by ReadDir.
	if pages, err := os.ReadFile("/proc/self/statm"); err == nil {
		var resident uint64
		if fields := bytes.Fields(pages); len(fields) >= 2 {
			resident, _ = strconv.ParseUint(string(fields[1]), 10, 64)
		}
		sample.RSS = resident * uint64(os.Getpagesize())
	}
	if raw, err := os.ReadFile("/proc/net/snmp"); err == nil {
		var names []string
		for line := range strings.SplitSeq(string(raw), "\n") {
			if !strings.HasPrefix(line, "Udp:") {
				continue
			}
			if names == nil {
				names = strings.Fields(line)
				continue
			}
			for i, value := range strings.Fields(line) {
				if i >= len(names) {
					break
				}
				count, _ := strconv.ParseUint(value, 10, 64)
				switch names[i] {
				case "InErrors":
					sample.KernelUDPErrors = count
				case "RcvbufErrors":
					sample.KernelUDPReadDrops = count
				case "SndbufErrors":
					sample.KernelUDPWriteDrops = count
				}
			}
			break
		}
	}
}

func processLoadCPU(t *testing.T) float64 {
	t.Helper()
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	return float64(usage.Utime.Nano()+usage.Stime.Nano()) / float64(time.Second)
}

func loadLoop(ctx context.Context, settings loadSettings, tunnel loadTunnel, echo netip.AddrPort, window int, traffic *loadTraffic) {
	var request, reply [1400]byte
	var sent [8]time.Time
	var sizes [8]int
	var sequence uint64
	peer := echo.Addr().As4()
	payloads := [...]int{64, 256, 1400, 1400}
	fixed, _ := strconv.Atoi(settings.workload)
	request[0], request[8], request[9] = 0x45, 64, 17
	copy(request[16:20], peer[:])
	binary.BigEndian.PutUint16(request[20:22], 26618)
	binary.BigEndian.PutUint16(request[22:24], echo.Port())
	binary.BigEndian.PutUint32(request[28:32], uint32(window))
	var pacer *time.Timer
	if settings.pause != 0 {
		pacer = time.NewTimer(time.Hour)
		pacer.Stop()
		defer pacer.Stop()
	}
	for ctx.Err() == nil {
		address := tunnel.address()
		if !address.Is4() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		source := address.As4()
		copy(request[12:16], source[:])
		batchCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		var queued int
		for i := range settings.batch {
			length := fixed
			if length == 0 {
				length = payloads[(sequence+uint64(i))%uint64(len(payloads))]
			}
			binary.BigEndian.PutUint16(request[2:4], uint16(length))
			binary.BigEndian.PutUint16(request[10:12], 0)
			binary.BigEndian.PutUint16(request[10:12], checksum(request[:20], 0))
			binary.BigEndian.PutUint16(request[24:26], uint16(length-20))
			binary.BigEndian.PutUint64(request[32:40], sequence+uint64(i))
			sent[i], sizes[i] = time.Now(), length
			if err := tunnel.app.WritePacket(batchCtx, request[:length]); err != nil {
				if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
					traffic.failed = true
				}
				break
			}
			queued++
		}
		traffic.sent += uint64(queued)
		var seen uint8
		for matched := 0; matched < queued; {
			n, err := tunnel.app.ReadPacket(batchCtx, reply[:])
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				break
			}
			if err != nil {
				traffic.failed = true
				cancel()
				return
			}
			if n < 40 || reply[0] != 0x45 || reply[9] != 17 ||
				string(reply[12:16]) != string(peer[:]) || string(reply[16:20]) != string(source[:]) ||
				binary.BigEndian.Uint16(reply[20:22]) != echo.Port() || binary.BigEndian.Uint16(reply[22:24]) != 26618 ||
				binary.BigEndian.Uint32(reply[28:32]) != uint32(window) {
				continue
			}
			id := binary.BigEndian.Uint64(reply[32:40])
			if id < sequence || id >= sequence+uint64(queued) {
				continue
			}
			index := id - sequence
			if n != sizes[index] || seen&(1<<index) != 0 {
				continue
			}
			seen |= 1 << index
			matched++
			arrived := time.Now()
			if traffic.firstResponse.IsZero() {
				traffic.firstResponse = arrived
			}
			traffic.received++
			traffic.payload += uint64(n - 28)
			switch n {
			case 64:
				traffic.receivedBySize[0]++
			case 256:
				traffic.receivedBySize[1]++
			case 1400:
				traffic.receivedBySize[2]++
			}
			traffic.latency.observe(arrived.Sub(sent[index]))
		}
		sequence += uint64(settings.batch)
		cancel()
		if pacer != nil {
			pacer.Reset(settings.pause)
			select {
			case <-ctx.Done():
				return
			case <-pacer.C:
			}
		}
	}
}
