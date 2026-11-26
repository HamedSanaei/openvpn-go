"""Check median measurements from the three samples produced by make bench."""

import argparse
from pathlib import Path
import re
from statistics import median
import sys

PACKET = {"ns/op": 10000, "B/op": 3300, "allocs/op": 4}
LIMITS = {
    "BenchmarkDataRoundTrip/AES-128-GCM": PACKET,
    "BenchmarkDataRoundTrip/AES-256-GCM": PACKET,
    "BenchmarkDataRoundTrip/CHACHA20-POLY1305": PACKET,
    "BenchmarkDiscardUnauthenticated": {"ns/op": 8000, "B/op": 1650, "allocs/op": 2},
    "BenchmarkIdleClient": {"ns/op": 150000, "B/op": 24576, "allocs/op": 185, "idle-B/client": 16384},
    "BenchmarkReconnect": {"ns/op": 5000000, "B/op": 4096, "allocs/op": 55},
}


def check(path):
    measurements = {name: [] for name in LIMITS}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) < 4 or not fields[0].startswith("Benchmark"):
            continue
        name = re.sub(r"-\d+$", "", fields[0])
        if name in measurements:
            measurements[name].append({unit: float(value) for value, unit in zip(fields[2::2], fields[3::2])})
    failures = []
    for name, samples in measurements.items():
        if len(samples) != 3:
            failures.append(f"{name} requires three samples")
            continue
        for metric, limit in LIMITS[name].items():
            if any(metric not in sample for sample in samples):
                failures.append(f"{name} is missing {metric}")
                continue
            value = median(sample[metric] for sample in samples)
            print(f"{name}  {value:g} {metric}  (limit {limit:g})")
            if not 0 <= value <= limit:
                failures.append(f"{name} exceeded the {metric} budget")
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        failures = check(args.log)
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))
    if failures:
        sys.exit("\n".join(failures))


if __name__ == "__main__":
    main()
