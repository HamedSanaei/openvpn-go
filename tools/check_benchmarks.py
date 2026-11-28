"""Check median measurements from the three samples produced by make bench."""

import argparse
from math import isfinite
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
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        fields = line.split()
        if not fields or not fields[0].startswith("Benchmark"):
            continue
        name = re.sub(r"-\d+$", "", fields[0])
        if name in measurements:
            if len(fields) < 4 or len(fields) % 2:
                raise ValueError(f"{name} line {line_no}: malformed benchmark row")
            iterations = fields[1]
            if not re.fullmatch(r"[0-9]+", iterations) or not iterations.lstrip("0"):
                raise ValueError(f"{name} line {line_no}: invalid benchmark iteration count")
            sample = {}
            for value, unit in zip(fields[2::2], fields[3::2], strict=True):
                if unit in sample:
                    raise ValueError(f"{name} line {line_no}: duplicate {unit} measurement")
                try:
                    number = float(value)
                except ValueError:
                    raise ValueError(f"{name} line {line_no}: invalid {unit} measurement") from None
                if not isfinite(number) or number < 0:
                    raise ValueError(f"{name} line {line_no}: invalid {unit} measurement")
                sample[unit] = number
            measurements[name].append(sample)
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
