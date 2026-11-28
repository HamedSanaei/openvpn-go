"""Compare native-load samples recorded on the same controlled runner."""

import argparse
import json
import math
from pathlib import Path
from statistics import median, pstdev
import sys


IP_SIZES = (64, 256, 1400)
PAYLOAD_SIZES = tuple(size - 28 for size in IP_SIZES)


def count(row, key, maximum=(1 << 64) - 1):
    value = row[key]
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"invalid {key} count")
    return value


def settings(row):
    managed = row.get("managed", False)
    if type(managed) is not bool:
        raise ValueError("invalid managed workload flag")
    network, workload = row["network"], row["workload"]
    if network not in ("udp", "tcp") or workload not in ("64", "256", "1400", "mixed"):
        raise ValueError("invalid network or packet workload")
    limits = (("sessions", 1000), ("window_packets", 8), ("configured_seconds", 3600),
              ("warmup_seconds", 600), ("expected_windows", 720), ("restart_every", 720),
              ("rekey_seconds", 3600), ("pause_us", 1000000))
    parameters = tuple(count(row, key, cap) for key, cap in limits)
    sessions, batch, seconds, _, windows = parameters[:5]
    if min(sessions, batch, seconds, windows) < 1 or windows * seconds > 72 * 3600:
        raise ValueError("invalid native load settings")
    return (network, workload) + parameters + (managed,)


def check_payload(row, received, octets):
    workload = row["workload"]
    if workload != "mixed" and octets != received * (int(workload) - 28):
        raise ValueError("payload_bytes does not match the fixed packet workload")
    if "received_by_size" in row:
        sizes = row["received_by_size"]
        if (type(sizes) is not list or len(sizes) != len(IP_SIZES) or
                any(type(n) is not int or not 0 <= n <= received for n in sizes) or
                sum(sizes) != received or
                sum(n * size for n, size in zip(sizes, PAYLOAD_SIZES)) != octets or
                (workload != "mixed" and sizes[IP_SIZES.index(int(workload))] != received)):
            raise ValueError("invalid received_by_size or payload_bytes accounting")
    elif workload == "mixed" and not received * PAYLOAD_SIZES[0] <= octets <= received * PAYLOAD_SIZES[-1]:
        raise ValueError("payload_bytes is outside the mixed packet workload bounds")


def report(directory, *, require_fds=False):
    environment = json.loads((directory / "environment.json").read_text())
    system = environment["system"]
    if environment["dirty"] or system["profiled"]:
        raise ValueError("comparison requires clean commits and unprofiled samples")
    rows = [json.loads(line) for line in (directory / "metrics.jsonl").read_text().splitlines()]
    if len(rows) < 3 or len(rows) != count(rows[0], "expected_windows", 720):
        raise ValueError("at least three windows and the complete sample set are required")
    workload = settings(rows[0])

    def numeric(row, key):
        value = row[key]
        if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
            raise ValueError(f"invalid {key} measurement")
        return value

    samples = {}
    for window, row in enumerate(rows, 1):
        if count(row, "window", 720) != window or settings(row) != workload:
            raise ValueError("non-consecutive or inconsistent windows")
        sent, received, octets, latency, failed, silent, rss = (
            count(row, key) for key in ("sent", "received", "payload_bytes", "p99_ns",
                                        "failed_tunnels", "silent_tunnels", "rss_bytes")
        )
        seconds, cpu = (numeric(row, key) for key in ("seconds", "driver_cpu_seconds"))
        if not (seconds >= row["configured_seconds"] * 0.99 and 0 < received <= sent and octets > 0 and
                0 < latency and 0 < cpu and 0 < rss and failed == silent == 0):
            raise ValueError("incomplete window, failed tunnel or missing measurement")
        check_payload(row, received, octets)
        values = {"payload_mbit_s": octets * 8 / seconds / 1e6, "cpu_s_per_gbit": cpu / (octets * 8 / 1e9),
                  "p99_ns": latency, "loss_ppm": (sent - received) * 1e6 / sent,
                  "rss_bytes": rss}
        if require_fds:
            values["fds"] = count(row, "fds")
        if values["payload_mbit_s"] <= 0 or values["cpu_s_per_gbit"] <= 0:
            raise ValueError("derived goodput or CPU efficiency underflow")
        for name, value in values.items():
            if not math.isfinite(value):
                raise ValueError(f"invalid derived {name}")
            samples.setdefault(name, []).append(value)
    stats = {name: {"median": median(values), "stddev": pstdev(values), "samples": len(values), "max": max(values)}
             for name, values in samples.items()}
    losses = samples["loss_ppm"]
    stats["loss_ppm"]["worst_window"] = losses.index(max(losses)) + 1
    return system, workload, stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--regression", type=float, default=0.10)
    parser.add_argument("--max-loss-ppm", type=float, required=True)
    parser.add_argument("--max-window-loss-ppm", type=float, help="cap the loss of each measured window")
    parser.add_argument("--max-rss-bytes", type=int, help="cap the RSS of each measured window")
    parser.add_argument("--max-fds", type=int, help="cap the descriptors of each measured window")
    args = parser.parse_args()
    if (not 0 < args.regression < 1 or not 0 <= args.max_loss_ppm <= 1e6 or
            (args.max_window_loss_ppm is not None and not 0 <= args.max_window_loss_ppm <= 1e6)):
        parser.error("invalid regression or loss budget")
    limits = {"rss_bytes": args.max_rss_bytes, "fds": args.max_fds}
    if any(limit is not None and limit <= 0 for limit in limits.values()):
        parser.error("resource ceilings must be positive")
    try:
        base_system, base_workload, base = report(args.baseline, require_fds=args.max_fds is not None)
        system, workload, candidate = report(args.candidate, require_fds=args.max_fds is not None)
        if (system, workload) != (base_system, base_workload):
            raise ValueError("machine, peer, settings or workload differ")
        print(json.dumps({"baseline": base, "candidate": candidate}, indent=2))
        fail = []
        if max(base["loss_ppm"]["median"], candidate["loss_ppm"]["median"]) > args.max_loss_ppm:
            fail.append("median loss budget")
        if args.max_window_loss_ppm is not None:
            for label, run in (("baseline", base), ("candidate", candidate)):
                loss = run["loss_ppm"]
                if loss["max"] > args.max_window_loss_ppm:
                    fail.append(f"{label} window {loss['worst_window']} loss {loss['max']:g} ppm "
                                f"exceeds {args.max_window_loss_ppm:g} ppm")
        for metric, limit in limits.items():
            if limit is not None and max(base[metric]["max"], candidate[metric]["max"]) > limit:
                fail.append(metric)
        if fail:
            raise ValueError("native load limit exceeded: " + ", ".join(fail))
        for name in ("payload_mbit_s", "cpu_s_per_gbit", "p99_ns"):
            ref, current = base[name], candidate[name]
            if max(ref["stddev"] / ref["median"], current["stddev"] / current["median"]) > args.regression:
                raise ValueError(f"{name} samples are too noisy for a threshold decision")
            direction = -1 if name == "payload_mbit_s" else 1
            if direction * (current["median"] / ref["median"] - 1) > args.regression:
                fail.append(name)
        if fail:
            raise ValueError("native load limit exceeded: " + ", ".join(fail))
    except (KeyError, OSError, OverflowError, TypeError, ValueError) as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
