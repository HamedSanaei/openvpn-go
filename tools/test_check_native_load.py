import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


class NativeLoadGateTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.baseline = self.root / "baseline"
        self.candidate = self.root / "candidate"
        for directory in (self.baseline, self.candidate):
            directory.mkdir()
            (directory / "environment.json").write_text(json.dumps({
                "dirty": False, "system": {"profiled": False, "runner": "synthetic"},
            }))
            self.write_samples(directory)

    def write_samples(self, directory, count=3, *, latency=200_000, cpu=1, managed=None, **updates):
        sample = {
            "network": "udp", "workload": "mixed", "sessions": 64,
            "window_packets": 4, "configured_seconds": 3, "warmup_seconds": 1,
            "expected_windows": 3, "restart_every": 0, "rekey_seconds": 0, "pause_us": 0,
            "seconds": 3, "sent": 1000, "received": 999, "payload_bytes": 700_000,
            "driver_cpu_seconds": cpu, "p99_ns": latency, "failed_tunnels": 0,
            "silent_tunnels": 0, "rss_bytes": 16 << 20, "fds": 16,
        }
        if managed is not None:
            sample["managed"] = managed
        sample.update(updates)
        (directory / "metrics.jsonl").write_text("".join(
            json.dumps(dict(sample, window=i)) + "\n" for i in range(1, count + 1)
        ))

    def run_gate(self, *options):
        return subprocess.run([
            sys.executable, str(Path(__file__).with_name("check_native_load.py")),
            str(self.baseline), str(self.candidate), "--max-loss-ppm", "2000",
            *options,
        ], capture_output=True, text=True, check=False)

    def set_sent_counts(self, directory, *counts):
        path = directory / "metrics.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        for row, sent in zip(rows, counts, strict=True):
            row["sent"] = sent
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))

    def test_comparable_samples_pass(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["candidate"]["p99_ns"]["samples"], 3)

    def test_missing_sample_fails(self):
        self.write_samples(self.candidate, count=2)
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("complete sample set", result.stderr)

    def test_nonfinite_sample_fails(self):
        self.write_samples(self.candidate, cpu=float("nan"))
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid driver_cpu_seconds", result.stderr)

    def test_latency_regression_fails(self):
        self.write_samples(self.candidate, latency=240_000)
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("p99_ns", result.stderr)

    def test_managed_and_direct_samples_are_not_comparable(self):
        self.write_samples(self.candidate, managed=True)
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("workload differ", result.stderr)

    def test_fixed_payload_cannot_be_inflated(self):
        self.write_samples(self.baseline, workload="1400", payload_bytes=999 * 1372)
        self.write_samples(self.candidate, workload="1400", payload_bytes=999 * 2744, cpu=2)
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fixed packet workload", result.stderr)

    def test_all_supported_workloads_pass_with_exact_histograms(self):
        for workload, bins in [
            ("64", [999, 0, 0]), ("256", [0, 999, 0]), ("1400", [0, 0, 999]),
            ("mixed", [199, 300, 500]),
        ]:
            with self.subTest(workload=workload):
                octets = sum(n * payload for n, payload in zip(bins, [36, 228, 1372]))
                for directory in (self.baseline, self.candidate):
                    self.write_samples(directory, workload=workload, payload_bytes=octets, received_by_size=bins)
                result = self.run_gate()
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_inconsistent_samples_fail(self):
        for sample in [
            {"received": 998.5}, {"sent": True}, {"sessions": "64"}, {"workload": "1550"},
            {"expected_windows": True}, {"window_packets": 9}, {"received_by_size": [True, 0, 998]},
            {"received_by_size": [1, 0, 998]}, {"received_by_size": [1, 0, 999]},
            {"workload": "mixed", "payload_bytes": 999 * 1372 + 1},
            {"driver_cpu_seconds": 1.7e308, "payload_bytes": 999 * 36},
            {"seconds": 1.7e308, "driver_cpu_seconds": 5e-324, "payload_bytes": 999 * 1372},
        ]:
            with self.subTest(sample=sample):
                self.write_samples(self.candidate, **sample)
                result = self.run_gate()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Traceback", result.stderr)

    def test_explicit_resource_ceilings(self):
        result = self.run_gate("--max-rss-bytes", str(16 << 20), "--max-fds", "16")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.write_samples(self.candidate, rss_bytes=17 << 20, fds=17)
        result = self.run_gate("--max-rss-bytes", str(16 << 20), "--max-fds", "16")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rss_bytes", result.stderr)
        self.assertIn("fds", result.stderr)

    def test_separate_window_loss_ceiling_catches_spike(self):
        for directory in (self.baseline, self.candidate):
            self.write_samples(directory, workload="1400", payload_bytes=999 * 1372)
        self.set_sent_counts(self.candidate, 1000, 1998, 1000)
        median = self.run_gate()
        self.assertEqual(median.returncode, 0, median.stderr)
        hard = self.run_gate("--max-window-loss-ppm", "2000")
        self.assertNotEqual(hard.returncode, 0)
        self.assertIn("candidate window 2 loss 500000 ppm exceeds 2000 ppm", hard.stderr)
        report = json.loads(hard.stdout)["candidate"]["loss_ppm"]
        self.assertEqual((report["median"], report["max"], report["worst_window"]), (1000, 500000, 2))

    def test_window_loss_boundary_and_unequal_packet_counts(self):
        self.set_sent_counts(self.baseline, 999, 1000, 1000)
        self.set_sent_counts(self.candidate, 999, 999, 1000)
        exact = self.run_gate("--max-window-loss-ppm", "1000")
        self.assertEqual(exact.returncode, 0, exact.stderr)
        below = self.run_gate("--max-window-loss-ppm", "999")
        self.assertNotEqual(below.returncode, 0)
        self.assertIn("baseline window 2 loss 1000 ppm", below.stderr)
        self.assertIn("candidate window 3 loss 1000 ppm", below.stderr)
        for directory in (self.baseline, self.candidate):
            self.set_sent_counts(directory, 999, 999, 999)
        zero = self.run_gate("--max-window-loss-ppm", "0")
        self.assertEqual(zero.returncode, 0, zero.stderr)


if __name__ == "__main__":
    unittest.main()
