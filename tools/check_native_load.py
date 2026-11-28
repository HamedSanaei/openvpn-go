"""Compare native-load samples recorded on the same controlled runner."""

import argparse
import json
import math
from pathlib import Path
from statistics import median, pstdev
import sys


def report(directory):
    environment = json.loads((directory / "environment.json").read_text())
    system = environment["system"]
    if environment["dirty"] or system["profiled"]:
        raise ValueError("comparison requires clean commits and unprofiled samples")
    rows = [json.loads(line) for line in (directory / "metrics.jsonl").read_text().splitlines()]
    if len(rows) < 3 or len(rows) != rows[0]["expected_windows"]:
        raise ValueError("at least three windows and the complete sample set are required")
    fields = ("network", "workload", "sessions", "window_packets", "configured_seconds", "warmup_seconds",
              "expected_windows", "restart_every", "rekey_seconds", "pause_us")
    def settings(row):
        managed = row.get("managed", False)
        if type(managed) is not bool:
            raise ValueError("invalid managed workload flag")
        return tuple(row[key] for key in fields) + (managed,)

    workload = settings(rows[0])

    def numeric(row, key):
        value = row[key]
        if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
            raise ValueError(f"invalid {key} measurement")
        return value

    samples = {}
    for window, row in enumerate(rows, 1):
        if row["window"] != window or settings(row) != workload:
            raise ValueError("non-consecutive or inconsistent windows")
        seconds, sent, received, octets, cpu, latency, failed, silent = (
            numeric(row, key) for key in ("seconds", "sent", "received", "payload_bytes", "driver_cpu_seconds",
                                          "p99_ns", "failed_tunnels", "silent_tunnels")
        )
        rss = numeric(row, "rss_bytes")
        if not (seconds >= row["configured_seconds"] * 0.99 and 0 < received <= sent and octets > 0 and
                0 < latency and 0 < cpu and 0 < rss and failed == silent == 0):
            raise ValueError("incomplete window, failed tunnel or missing measurement")
        values = {"payload_mbit_s": octets * 8 / seconds / 1e6, "cpu_s_per_gbit": cpu / (octets * 8 / 1e9),
                  "p99_ns": latency, "loss_ppm": (sent - received) * 1e6 / sent,
                  "rss_bytes": rss}
        for name, value in values.items():
            samples.setdefault(name, []).append(value)
    stats = {name: {"median": median(values), "stddev": pstdev(values), "samples": len(values)}
             for name, values in samples.items()}
    return system, workload, stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--regression", type=float, default=0.10)
    parser.add_argument("--max-loss-ppm", type=float, required=True)
    args = parser.parse_args()
    if not 0 < args.regression < 1 or not 0 <= args.max_loss_ppm <= 1e6:
        parser.error("invalid regression or loss budget")
    try:
        base_system, base_workload, base = report(args.baseline)
        system, workload, candidate = report(args.candidate)
        if (system, workload) != (base_system, base_workload):
            raise ValueError("machine, peer, settings or workload differ")
        print(json.dumps({"baseline": base, "candidate": candidate}, indent=2))
        fail = []
        for name in ("payload_mbit_s", "cpu_s_per_gbit", "p99_ns"):
            ref, current = base[name], candidate[name]
            if max(ref["stddev"] / ref["median"], current["stddev"] / current["median"]) > args.regression:
                raise ValueError(f"{name} samples are too noisy for a threshold decision")
            direction = -1 if name == "payload_mbit_s" else 1
            if direction * (current["median"] / ref["median"] - 1) > args.regression:
                fail.append(name)
        if max(base["loss_ppm"]["median"], candidate["loss_ppm"]["median"]) > args.max_loss_ppm:
            fail.append("loss budget")
        if fail:
            raise ValueError("native load limit exceeded: " + ", ".join(fail))
    except (KeyError, OSError, TypeError, ValueError) as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
