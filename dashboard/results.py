"""Reads results/summary.csv and works out mean and standard deviation (Section 9).

Columns: protocol, condition, run, throughput_mbps, rtt_ms, loss_pct. One row per run.
We use the SAMPLE standard deviation (divide by n-1). With one run it is 0.
"""
import csv
import math
import os

COLUMNS = ["protocol", "condition", "run", "throughput_mbps", "rtt_ms", "loss_pct"]
METRICS = ["throughput_mbps", "rtt_ms", "loss_pct"]


class ResultsError(Exception):
    """The file exists but cannot be understood. The message is shown on the page."""


def mean_std(values):
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, 0.0
    return mean, math.sqrt(sum((v - mean) ** 2 for v in values) / (n - 1))


def read_results(path):
    """Returns {"available": False} if the file is missing or has no data rows, else the summary.

    Protocols and conditions keep the order in which they first appear in the file.
    """
    if not os.path.isfile(path):
        return {"available": False}
    try:
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            missing = [c for c in COLUMNS if c not in (reader.fieldnames or [])]
            if missing:
                raise ResultsError("summary.csv is missing columns: " + ", ".join(missing))
            rows = list(reader)
    except (OSError, UnicodeDecodeError, csv.Error) as e:
        raise ResultsError(f"cannot read summary.csv: {e}")
    if not rows:
        return {"available": False}

    protocols, conditions, groups, runs = [], [], {}, set()
    for i, row in enumerate(rows, start=2):                      # line 1 is the header
        try:
            nums = {m: float(row[m]) for m in METRICS}
        except (TypeError, ValueError):
            raise ResultsError(f"summary.csv line {i}: a number is missing or not a number")
        if not all(math.isfinite(v) for v in nums.values()):
            raise ResultsError(f"summary.csv line {i}: a number is not finite")
        p, c = row["protocol"].strip(), row["condition"].strip()
        if p not in protocols:
            protocols.append(p)
        if c not in conditions:
            conditions.append(c)
        runs.add((p, c, row["run"].strip()))
        groups.setdefault((p, c), {m: [] for m in METRICS})
        for m in METRICS:
            groups[(p, c)][m].append(nums[m])

    stats = []
    for (p, c), g in groups.items():
        entry = {"protocol": p, "condition": c, "runs": len(g["rtt_ms"])}
        for m in METRICS:
            entry[m] = dict(zip(("mean", "std"), mean_std(g[m])))
        stats.append(entry)
    return {"available": True, "protocols": protocols, "conditions": conditions,
            "max_runs": max(e["runs"] for e in stats), "stats": stats}
