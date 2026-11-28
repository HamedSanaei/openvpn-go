"""Record scheduler and visible cgroup v2 CPU constraints of live processes."""

import json
import os
from pathlib import Path
import sys


def cpu_groups(pid):
    proc = Path("/proc") / str(pid)
    groups = (proc / "cgroup").read_text().splitlines()
    group = next((Path(row[3:]) for row in groups if row.startswith("0::")), None)
    if group is None or not group.is_absolute() or ".." in group.parts:
        raise ValueError("participant cgroup v2 is unavailable")
    for line in (proc / "mountinfo").read_text().splitlines():
        prefix, marker, suffix = line.partition(" - ")
        if not marker or suffix.split()[0] != "cgroup2":
            continue
        root, mount = prefix.split()[3:5]
        if root != "/" or "\\" in mount:
            continue
        path = proc / "root" / mount.lstrip("/")
        leaf = path.joinpath(*group.parts[1:])
        cpus = leaf / "cpuset.cpus.effective"
        if not cpus.is_file():
            continue
        quotas = []
        for ancestor in (leaf, *leaf.parents):
            setting = ancestor / "cpu.max"
            if setting.is_file():
                quota, period = setting.read_text().split()
                if quota != "max":
                    quotas.append([int(quota), int(period)])
            if ancestor == path:
                break
        return sorted(set(map(tuple, quotas))), cpus.read_text().strip()
    raise ValueError("participant cgroup CPU hierarchy or effective cpuset is unavailable")


def snapshot(pid):
    quotas, cpuset = cpu_groups(pid)
    return {
        "scheduler": os.sched_getscheduler(pid),
        "nice": os.getpriority(os.PRIO_PROCESS, pid),
        "affinity": sorted(os.sched_getaffinity(pid)),
        "quota_period_us": quotas,
        "cpuset_effective": cpuset,
    }


if __name__ == "__main__":
    try:
        driver, peer = map(int, sys.argv[1:])
        print(json.dumps({"driver": snapshot(driver), "peer": snapshot(peer)}, sort_keys=True))
    except (OSError, ValueError):
        # OS errors may include process paths. Keep the public diagnostic stable.
        sys.exit("unable to verify native-load scheduling constraints")
