//go:build linux

package interop_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

type workload struct {
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	Seconds  float64 `json:"seconds"`
}

type clientSample struct {
	Client string `json:"client"`
	Mode   string `json:"mode"`
	workload
	Mbps         float64 `json:"payload_mbps"`
	CPUSeconds   float64 `json:"client_cpu_seconds"`
	PeakRSSBytes int64   `json:"peak_rss_bytes"`
	ReconnectMS  int64   `json:"reconnect_ms"`
}

// TestComparativeBenchmark samples three distinct userspace clients
// against the same regenerated isolated peer and application workload.
func TestComparativeBenchmark(t *testing.T) {
	goClient, core := os.Getenv("OPENVPN_GO_BENCH_BIN"), os.Getenv("OPENVPN3_INTEROP_BIN")
	if goClient == "" {
		t.Skip("set OPENVPN_GO_BENCH_BIN to a local ovpn-xray build")
	}
	peer := interopPeer(t)
	digest := os.Getenv("OPENVPN3_INTEROP_SHA256")
	if core == "" || digest == "" {
		t.Fatal("a checksum-pinned OpenVPN 3 Core build is required")
	}
	coreHash := verifyCoreBuild(t, core, digest)
	output, err := exec.Command("getconf", "CLK_TCK").Output()
	ticks, parseErr := strconv.ParseFloat(strings.TrimSpace(string(output)), 64)
	if err != nil || parseErr != nil || ticks <= 0 {
		t.Fatal("could not read CPU tick frequency")
	}
	t.Logf("host=linux/%s go=%s peer_sha256=%s core_sha256=%s target_go_sha256=%s", runtime.GOARCH, runtime.Version(),
		binarySHA256(t, peer), coreHash, binarySHA256(t, goClient))
	ns := prepareCoreNamespace(t)
	for _, scenario := range []struct{ name, binary string }{
		{"openvpn2", peer}, {"openvpn3", core}, {"go", goClient},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			pki := testkit.NewPKI(t)
			f := makePKIFixture(t, peer, pki)
			port := localPort(t, "udp")
			startPeer := func() func() {
				stop := f.launch(t, port, "udp", "tls", false, "--local", labServer, "--dev", "tun-bench",
					"--keepalive", "1", "4", "--verb", "3")
				configureLink(t, "tun-bench", labEcho+"/24")
				return stop
			}
			stopPeer := startPeer()
			echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(labEcho)})
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			echo.SetReadBuffer(1 << 20)
			echoDone := make(chan struct{})
			go func() {
				defer close(echoDone)
				var payload [1536]byte
				for {
					n, from, err := echo.ReadFromUDP(payload[:])
					if err != nil {
						return
					}
					echo.WriteToUDP(payload[:n], from)
				}
			}()
			defer func() { echo.Close(); <-echoDone }()
			profileText, _ := coreProfile(t, f, conformanceCase{network: "udp", protection: "tls", tlsVersion: "1.2", cipher: "AES-256-GCM"}, pki, port)
			path := filepath.Join(f.dir, "benchmark.ovpn")
			if err := os.WriteFile(path, []byte(profileText), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{path}
			switch scenario.name {
			case "openvpn2":
				args = []string{"--config", path, "--disable-dco", "--verb", "3"}
			case "openvpn3":
				args = []string{"--timeout", "12", path}
			case "go":
				testIP(t, "-n", ns, "tuntap", "add", "dev", "bench-go", "mode", "tun")
				testIP(t, "-n", ns, "address", "add", "10.49.0.2/24", "dev", "bench-go")
				testIP(t, "-n", ns, "link", "set", "bench-go", "up")
				t.Cleanup(func() { exec.Command("ip", "-n", ns, "link", "del", "bench-go").Run() })
				args = []string{"-profile", path, "-tun", "bench-go", "-ipv4", "10.49.0.2", "-attempts", "-1"}
			}
			log, err := os.Create(filepath.Join(f.dir, "bench-client.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			cmd := exec.Command("ip", append([]string{"netns", "exec", ns, scenario.binary}, args...)...)
			cmd.Stdout, cmd.Stderr = log, log
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					cmd.Process.Kill()
					cmd.Wait()
				}
				if t.Failed() {
					raw, _ := os.ReadFile(log.Name())
					t.Log(string(raw))
				}
			}()
			awaitBenchEcho(t, ns, echo, 15*time.Second)
			before := processCPU(t, cmd.Process.Pid)
			work, err := benchTraffic(t.Context(), ns, echo, 4096)
			if err != nil {
				t.Fatal(err)
			}
			elapsedCPU := float64(processCPU(t, cmd.Process.Pid)-before) / ticks
			stopPeer()
			restart := time.Now()
			startPeer()
			awaitBenchEcho(t, ns, echo, 22*time.Second)
			reconnect := time.Since(restart).Milliseconds()
			cmd.Process.Kill()
			cmd.Wait()
			waited = true
			rss := cmd.ProcessState.SysUsage().(*syscall.Rusage).Maxrss * 1024
			sample := clientSample{Client: scenario.name, Mode: "userspace", workload: work,
				Mbps: float64(work.Received) * 1200 * 8 / 1e6 / work.Seconds, CPUSeconds: elapsedCPU,
				PeakRSSBytes: rss, ReconnectMS: reconnect}
			raw, err := json.Marshal(sample)
			if err != nil {
				t.Fatal(err)
			}
			t.Log(string(raw))
			if work.Received < work.Sent*98/100 || work.Seconds <= 0 ||
				scenario.name == "go" && (rss > 96<<20 || reconnect > 20000) {
				t.Fatal("userspace resource or delivery budget exceeded")
			}
		})
	}
}

func processCPU(t *testing.T, pid int) uint64 {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	row := string(raw)
	i := strings.LastIndexByte(row, ')')
	if i < 0 {
		t.Fatal("invalid process stat")
	}
	fields := strings.Fields(row[i+1:])
	if len(fields) < 13 {
		t.Fatal("truncated process stat")
	}
	user, a := strconv.ParseUint(fields[11], 10, 64)
	kernel, b := strconv.ParseUint(fields[12], 10, 64)
	if a != nil || b != nil {
		t.Fatal("invalid CPU counters")
	}
	return user + kernel
}

func awaitBenchEcho(t *testing.T, ns string, echo *net.UDPConn, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	for ctx.Err() == nil {
		if report, err := benchTraffic(ctx, ns, echo, 1); err == nil && report.Received == 1 {
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("tunnel echo did not become available before its deadline")
}

func benchTraffic(ctx context.Context, ns string, echo *net.UDPConn, count int) (workload, error) {
	port := strconv.Itoa(echo.LocalAddr().(*net.UDPAddr).Port)
	raw, err := exec.CommandContext(ctx, "ip", "netns", "exec", ns, "python3", "bench_traffic.py", labEcho, port, strconv.Itoa(count)).Output()
	var result workload
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(raw, &result)
	return result, err
}
