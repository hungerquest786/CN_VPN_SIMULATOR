#!/usr/bin/env python3
"""Run all measurements (Section 11).  Run with sudo, from anywhere.

  sudo python3 lab/run_experiments.py                    # full: 5 modes x 3 conditions x 3 runs = 45 runs
  sudo python3 lab/run_experiments.py --quick            # 1 run, 3 s iperf3, 10 pings -> results/quick/
  sudo python3 lab/run_experiments.py --modes plain gre --conditions good --runs 2

For every mode (lab/switch.py), every condition (lab/netem.sh preset) and every run it measures:
  - throughput: iperf3 TCP from client1 to serverA's target address (what `switch.py status` reports)
  - delay and loss: ping from client1 to the same address
A short warm-up ping comes first, so handshakes (WireGuard, OpenVPN) are not counted.
If any step fails the script stops, says which step, and runs `switch.py off` and `netem.sh off`.
"""
import argparse
import csv
import datetime
import json
import math
import os
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SWITCH = os.path.join(HERE, "switch.py")
NETEM = os.path.join(HERE, "netem.sh")
RESULTS = os.path.join(ROOT, "results")

CLIENT_NS, SERVER_NS = "client1", "serverA"

# mode -> name in the CSV. The order here is the order of the runs and of the rows in summary.csv
# (the same order as tests/fake_summary.csv, so the dashboard lists them the same way).
PROTOCOLS = {"plain": "Plain", "minivpn": "Mini VPN", "wireguard": "WireGuard", "openvpn": "OpenVPN", "gre": "GRE"}
# "none" = no impairment at all (netem.sh off), for a clean overhead comparison. It comes first, so the dashboard
# lists it first. The other three are the presets in lab/netem.sh, unchanged.
CONDITIONS = ["none", "good", "normal", "bad"]
NETEM_ARG = {"none": "off"}                             # what to give netem.sh for conditions with another name
CSV_COLUMNS = ["protocol", "condition", "run", "throughput_mbps", "rtt_ms", "loss_pct"]
# results/rtt_detail.csv: one row per run, worked out from the single ping replies (the main CSV keeps only the mean)
DETAIL_COLUMNS = ["protocol", "condition", "run", "rtt_min_ms", "rtt_median_ms", "rtt_p95_ms", "rtt_max_ms",
                  "replies_over_100ms"]
SPIKE_MS = 100

STALL_FACTOR = 3          # a step that took more than 3x its time limit means the clock jumped (VM paused)
SLOW_RUN_FACTOR = 2       # a run that took more than 2x the expected time gets a warning and a note
SETTLE_SECONDS = 2        # pause between ping and iperf3 so queued packets are gone
SWITCH_TIMEOUT = 180      # seconds for one `switch.py` call


class ParseError(Exception):
    """The output of iperf3 or ping could not be understood."""


class IperfConnectError(ParseError):
    """iperf3 could not connect (error in its JSON, or no connected stream). Worth one retry."""


class StepFailed(Exception):
    """One step of the experiment failed. `step` says which one, `detail` is what we saw."""
    def __init__(self, step, detail=""):
        super().__init__(step)
        self.step = step
        self.detail = detail


# ---------- parsing and statistics (no root needed, tested in tests/test_experiments.py) ----------

def parse_iperf3_json(text):
    """iperf3 -J output -> throughput in Mbit/s, as measured by the receiver (what actually arrived).

    A test that connected but where nothing arrived gives 0.0: that is a result, not an error.
    No connection (an error in the JSON, or no connected stream) raises IperfConnectError.
    """
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ParseError(f"iperf3 output is not JSON ({e})")
    if not isinstance(data, dict):
        raise ParseError("iperf3 JSON is not an object")
    if data.get("error"):
        raise IperfConnectError(f"iperf3 reported an error: {data['error']}")
    if not (isinstance(data.get("start"), dict) and data["start"].get("connected")):
        raise IperfConnectError("iperf3 never connected (no connected stream in the JSON)")
    try:
        bps = float(data["end"]["sum_received"]["bits_per_second"])
    except (KeyError, TypeError, ValueError):
        raise ParseError("no end.sum_received.bits_per_second in the iperf3 JSON")
    return max(bps, 0.0) / 1e6


def parse_ping(text):
    """Linux (iputils) ping output -> dict with sent, received, loss_pct and the RTT numbers in ms.

    loss_pct is worked out from the two counts (ping itself rounds it). The RTT values are None
    when no reply came back, because ping then prints no rtt line.
    """
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", text)
    if not m:
        raise ParseError("no 'packets transmitted, received' line in the ping output")
    sent, received = int(m.group(1)), int(m.group(2))
    if sent == 0:
        raise ParseError("ping sent 0 packets")
    out = {"sent": sent, "received": received,
           "loss_pct": max(0.0, 100.0 * (sent - received) / sent),
           "rtt_min_ms": None, "rtt_avg_ms": None, "rtt_max_ms": None, "rtt_mdev_ms": None}
    r = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", text)
    if r:
        out["rtt_min_ms"], out["rtt_avg_ms"], out["rtt_max_ms"], out["rtt_mdev_ms"] = (float(x) for x in r.groups())
    elif received > 0:
        raise ParseError("replies came back but there is no 'rtt min/avg/max/mdev' line")
    return out


def parse_ping_times(text):
    """All single reply times in ms ('time=33.2 ms' lines). Duplicate replies (DUP!) are left out."""
    return [float(m.group(1)) for line in text.splitlines() if "DUP!" not in line
            for m in [re.search(r"\btime=([\d.]+)\s*ms", line)] if m]


def rtt_stats(times):
    """min, median, p95 (nearest rank: the value at position ceil(0.95 * n)), max, and how many are over SPIKE_MS."""
    if not times:
        raise ValueError("no reply times")
    t = sorted(times)
    return {"rtt_min_ms": t[0], "rtt_median_ms": statistics.median(t),
            "rtt_p95_ms": t[math.ceil(0.95 * len(t)) - 1], "rtt_max_ms": t[-1],
            "replies_over_100ms": sum(1 for x in t if x > SPIKE_MS)}


def mean_sd(values):
    """Mean and SAMPLE standard deviation (n-1). With one value the deviation is 0 (same as the dashboard)."""
    values = list(values)
    if not values:
        raise ValueError("no values")
    mean = statistics.fmean(values)
    return mean, (statistics.stdev(values) if len(values) > 1 else 0.0)


def summarise(rows):
    """rows (dicts with the CSV columns) -> {(protocol, condition): {"runs": n, metric: (mean, sd)}}.
    Keys keep the order in which they first appear."""
    groups = {}
    for r in rows:
        groups.setdefault((r["protocol"], r["condition"]), []).append(r)
    out = {}
    for key, rs in groups.items():
        entry = {"runs": len(rs)}
        for metric in ("throughput_mbps", "rtt_ms", "loss_pct"):
            entry[metric] = mean_sd(r[metric] for r in rs)
        out[key] = entry
    return out


def csv_row(row):
    """One row as a list of text cells, in the column order of tests/fake_summary.csv."""
    return [row["protocol"], row["condition"], str(row["run"]),
            f"{row['throughput_mbps']:.3f}", f"{row['rtt_ms']:.3f}", f"{row['loss_pct']:.3f}"]


def detail_row(row, stats):
    """One rtt_detail.csv row as text cells (same protocol/condition/run as the main CSV row)."""
    return [row["protocol"], row["condition"], str(row["run"]), f"{stats['rtt_min_ms']:.3f}",
            f"{stats['rtt_median_ms']:.3f}", f"{stats['rtt_p95_ms']:.3f}", f"{stats['rtt_max_ms']:.3f}",
            str(stats["replies_over_100ms"])]


def write_detail_csv(path, details):
    """details: list of (row, stats) pairs."""
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(DETAIL_COLUMNS)
        for row, stats in details:
            w.writerow(detail_row(row, stats))


def write_summary_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(CSV_COLUMNS)
        for r in rows:
            w.writerow(csv_row(r))


def make_table_md(rows, settings, details=None):
    """results/table.md: mean ± SD per protocol and condition, one table per metric.
    details = list of (row, stats) pairs from the single ping replies; with it the table also shows the
    median and minimum RTT of each run (mean ± SD over the runs)."""
    stats = summarise(rows)
    protocols = list(dict.fromkeys(p for p, _ in stats))
    conditions = list(dict.fromkeys(c for _, c in stats))
    runs = sorted({e["runs"] for e in stats.values()})
    runs_text = str(runs[0]) if len(runs) == 1 else "/".join(str(n) for n in runs)
    lines = ["# Results: mean ± standard deviation", "",
             f"Each cell: mean ± sample standard deviation (n-1) over {runs_text} runs.",
             f"Throughput: iperf3 TCP, {settings['iperf_seconds']} s, client1 to serverA, receiver side. "
             f"Delay and loss: {settings['ping_count']} pings, {settings['ping_interval']} s apart, per run.",
             f"Loss is worked out from {settings['ping_count']} pings, so one run can only show steps of "
             f"{100 / settings['ping_count']:g} percentage points.",
             "Retries and other unusual events are listed in notes.txt.", ""]
    # every table is: (title, note, {(protocol, condition): (mean, sd)}, digits)
    tables = [("Throughput (Mbit/s)", None, {k: e["throughput_mbps"] for k, e in stats.items()}, 2),
              ("Mean RTT (ms)", "Each run's mean of its pings. A few late replies pull the mean up "
                                "(see the median and the minimum below).", {k: e["rtt_ms"] for k, e in stats.items()}, 1)]
    if details:
        groups = {}
        for row, st in details:
            groups.setdefault((row["protocol"], row["condition"]), []).append(st)
        for title, note, key in (("Median RTT (ms)", "Each run's median of its pings: much less moved by a few spikes than the mean.",
                                  "rtt_median_ms"),
                                 ("Minimum RTT (ms)", "Each run's fastest ping: the closest to the delay the "
                                                      "network adds with nothing in the way.", "rtt_min_ms")):
            tables.append((title, note, {k: mean_sd(st[key] for st in v) for k, v in groups.items()}, 1))
    tables.append(("Packet loss (%)", None, {k: e["loss_pct"] for k, e in stats.items()}, 2))
    for title, note, values, digits in tables:
        lines += [f"## {title}", ""] + ([note, ""] if note else []) + [
            "| Protocol | " + " | ".join(conditions) + " |", "|---|" + "---|" * len(conditions)]
        for p in protocols:
            cells = []
            for c in conditions:
                v = values.get((p, c))
                cells.append("-" if v is None else f"{v[0]:.{digits}f} ± {v[1]:.{digits}f}")
            lines.append(f"| {p} | " + " | ".join(cells) + " |")
        lines.append("")
    zeros = [(p, c, sum(1 for r in rows if r["protocol"] == p and r["condition"] == c and r["throughput_mbps"] == 0),
              e["runs"]) for (p, c), e in stats.items()]
    zeros = [z for z in zeros if z[2]]
    if zeros:
        lines += ["## Notes", ""] + [f"- {p} / {c}: {n} of {total} runs connected but received 0 bytes "
                                      f"(counted as 0 Mbit/s in the mean and SD)." for p, c, n, total in zeros] + [""]
    return "\n".join(lines)


def expected_run_seconds(settings):
    """About how long one run (warm-up, pings, pause, iperf3) takes."""
    return (1.5 + settings["ping_count"] * settings["ping_interval"] + 1.5       # warm-up, pings, ping wait
            + SETTLE_SECONDS + settings["iperf_seconds"] + 3.5)                  # iperf3 start and end


def stall_message(elapsed, limit):
    """Text if `elapsed` clock seconds for a step limited to `limit` seconds means the clock jumped, else None.
    (A VM that was paused wakes up with the clock far ahead, and every timeout fires at once.)"""
    if elapsed > STALL_FACTOR * limit:
        return (f"the clock moved {fmt_duration(elapsed)} during a step limited to {limit:g} s: the VM was probably "
                f"paused or the clock jumped. Results around this time are not valid, run again")
    return None


def slow_run_note(elapsed, expected):
    """Text if one run took much longer than expected (a shorter VM pause does not time anything out), else None."""
    if elapsed > SLOW_RUN_FACTOR * expected:
        return (f"slow run: {fmt_duration(elapsed)} instead of about {fmt_duration(expected)}. The VM may have paused "
                f"or the clock jumped, so check this run (and its RTT spikes) before trusting it")
    return None


def estimate_seconds(settings, n_modes, n_conditions):
    """A rough guess before the run starts (the real time is shown while it runs)."""
    per_run = expected_run_seconds(settings)
    per_block = 1.0                                                              # netem
    per_mode = 15.0                                                              # switch.py up and off
    return n_modes * (per_mode + n_conditions * (per_block + settings["runs"] * per_run))


def fmt_duration(seconds):
    seconds = int(round(seconds))
    return f"{seconds // 60} min {seconds % 60:02d} s" if seconds >= 60 else f"{seconds} s"


# ---------- the experiment ----------

def text_of(value):
    """Output kept by a timed-out subprocess can be bytes, str or None."""
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def timeout_detail(limit, started, what):
    """The StepFailed text for a timeout. `started` is time.time() at the start of the step."""
    base = f"no answer after {limit:g} s: {what}"
    stall = stall_message(time.time() - started, limit)
    return f"{stall} ({base})" if stall else base


def tail_text(text, n=6):
    return " | ".join(text.strip().splitlines()[-n:])


def read_text(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def write_text(path, text):
    with open(path, "w") as f:
        f.write(text)


class Experiment:
    def __init__(self, modes, conditions, settings, out_dir, say=print):
        self.modes, self.conditions, self.settings = modes, conditions, settings
        self.out = out_dir
        self.raw = os.path.join(out_dir, "raw")
        self.say = say
        self.children = []          # background processes (iperf3 servers) to stop at the end
        self.rows = []
        self.details = []           # (row, rtt stats) per run -> results/rtt_detail.csv
        self.notes = []             # unusual events (zero throughput, retries) -> results/notes.txt
        self.partial_path = os.path.join(out_dir, "summary.partial.csv")
        self.started = None

    # --- small helpers ---
    def sh(self, step, argv, timeout, log=None):
        """Run a command; stop with StepFailed if it fails or hangs. Returns (stdout, stderr)."""
        started = time.time()
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            detail = timeout_detail(timeout, started, " ".join(argv))
            if log:      # keep what the command printed before it was stopped
                write_text(log, f"$ {' '.join(argv)}\n{text_of(e.stdout)}{text_of(e.stderr)}\n(timed out: {detail})\n")
            raise StepFailed(step, detail)
        except FileNotFoundError:
            raise StepFailed(step, f"{argv[0]}: command not found")
        if log:
            write_text(log, f"$ {' '.join(argv)}\n{p.stdout}{p.stderr}\n(exit code {p.returncode})\n")
        if p.returncode != 0:
            raise StepFailed(step, tail_text(p.stdout + "\n" + p.stderr) or f"exit code {p.returncode}")
        return p.stdout, p.stderr

    def ns(self, namespace, *argv):
        return ["ip", "netns", "exec", namespace] + list(argv)

    # --- steps ---
    def switch_mode(self, mode):
        self.sh(f"switch to mode {mode} (switch.py {mode})", [sys.executable, SWITCH, mode], SWITCH_TIMEOUT,
                log=os.path.join(self.raw, f"switch-{mode}.log"))
        out, _ = self.sh(f"check mode {mode} (switch.py status)", [sys.executable, SWITCH, "status"], 60,
                         log=os.path.join(self.raw, f"status-{mode}.txt"))
        m = re.search(r"^target IP:\s+(\S+)", out, re.M)
        if not m:
            raise StepFailed(f"read the target address from switch.py status ({mode})", tail_text(out))
        return m.group(1)

    def set_netem(self, condition):
        arg = NETEM_ARG.get(condition, condition)
        self.sh(f"apply network condition '{condition}' (netem.sh {arg})", [NETEM, arg], 30)

    def warm_up(self, target, tag):
        """Ping until something comes back (so a WireGuard or OpenVPN handshake is finished). Up to 3 tries."""
        log = os.path.join(self.raw, f"{tag}.warmup.txt")
        seen = ""
        for attempt in range(3):
            started = time.time()
            try:
                p = subprocess.run(self.ns(CLIENT_NS, "ping", "-n", "-c", "3", "-i", "0.2", "-W", "3", target),
                                   capture_output=True, text=True, timeout=30)
            except subprocess.TimeoutExpired:
                raise StepFailed(f"warm-up ping from {CLIENT_NS} to {target}",
                                 timeout_detail(30, started, "warm-up ping"))
            seen += f"--- try {attempt + 1}\n{p.stdout}{p.stderr}\n"
            write_text(log, seen)
            try:
                if parse_ping(p.stdout)["received"] > 0:
                    return
            except ParseError:
                pass
        raise StepFailed(f"warm-up ping from {CLIENT_NS} to {target}", "no reply in 3 tries. See " + log)

    def measure_ping(self, target, tag):
        n, interval = self.settings["ping_count"], self.settings["ping_interval"]
        step = f"ping {target} ({n} packets)"
        out, _ = self.sh(step, self.ns(CLIENT_NS, "ping", "-n", "-c", str(n), "-i", str(interval), "-W", "3", target),
                         n * interval + 30, log=os.path.join(self.raw, f"{tag}.ping.txt"))
        try:
            r = parse_ping(out)
        except ParseError as e:
            raise StepFailed(step, str(e))
        if r["sent"] != n:
            raise StepFailed(step, f"ping sent {r['sent']} packets, expected {n}")
        if r["received"] == 0:
            raise StepFailed(step, "no reply to any of the pings")
        times = parse_ping_times(out)
        if not times:
            raise StepFailed(step, "replies counted, but no 'time=... ms' lines found in the ping output")
        if len(times) != r["received"]:
            self.notes.append(f"{tag}: ping counted {r['received']} replies but {len(times)} 'time=' lines were "
                              f"found (the RTT median/min/p95 use the lines)")
        r["stats"] = rtt_stats(times)
        return r

    def measure_iperf3(self, target, tag, run_label=""):
        """One iperf3 measurement. Retries ONCE, and only if iperf3 could not connect. A test that connected
        but received nothing is recorded as 0 (never retried: retrying bad luck would push results upward).
        Anything unusual is added to self.notes."""
        secs = self.settings["iperf_seconds"]
        step = f"iperf3 to {target} ({secs} s)"
        try:
            mbps = self.iperf3_attempt(target, tag, step)
        except IperfConnectError as first:
            self.keep_first_attempt(tag)
            self.say(f"   iperf3 could not connect ({first}); trying once more")
            try:
                mbps = self.iperf3_attempt(target, tag, step)
            except IperfConnectError as second:
                raise StepFailed(step, f"could not connect twice. First: {first}. Second: {second}")
            self.notes.append(f"{run_label or tag}: iperf3 could not connect the first time ({first}); "
                              f"the retry worked. First attempt kept in raw/{tag}.*.attempt1.*")
        except ParseError as e:
            raise StepFailed(step, str(e))
        if mbps == 0:
            self.notes.append(f"{run_label or tag}: iperf3 connected but 0 bytes arrived at the receiver "
                              f"(recorded as 0 Mbit/s)")
        return mbps

    def keep_first_attempt(self, tag):
        """Rename the files of a failed first attempt so the retry does not overwrite them."""
        for suffix in ("iperf3.json", "iperf3-server.log"):
            src = os.path.join(self.raw, f"{tag}.{suffix}")
            if os.path.exists(src):
                base, ext = suffix.split(".", 1)
                os.replace(src, os.path.join(self.raw, f"{tag}.{base}.attempt1.{ext}"))

    def iperf3_attempt(self, target, tag, step):
        """Start a one-off server in serverA, run the client in client1, return Mbit/s.
        Raises IperfConnectError if iperf3 could not connect, StepFailed for anything else that goes wrong."""
        secs = self.settings["iperf_seconds"]
        server_log = os.path.join(self.raw, f"{tag}.iperf3-server.log")
        with open(server_log, "wb") as logf:
            server = subprocess.Popen(self.ns(SERVER_NS, "iperf3", "-s", "-1", "--forceflush"), stdout=logf,
                                      stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        self.children.append(server)
        try:
            end = time.time() + 5
            while "Server listening" not in read_text(server_log):
                if server.poll() is not None or time.time() > end:
                    raise StepFailed(f"start the iperf3 server in {SERVER_NS}", tail_text(read_text(server_log))
                                     or "no output")
                time.sleep(0.1)
            json_path = os.path.join(self.raw, f"{tag}.iperf3.json")
            started = time.time()
            try:
                p = subprocess.run(self.ns(CLIENT_NS, "iperf3", "-c", target, "-t", str(secs), "-J"),
                                   capture_output=True, text=True, timeout=secs + 30)
            except subprocess.TimeoutExpired:
                raise StepFailed(step, timeout_detail(secs + 30, started, "iperf3 client"))
            write_text(json_path, p.stdout + (("\n# stderr:\n" + p.stderr) if p.stderr else ""))
            try:
                mbps = parse_iperf3_json(p.stdout)
            except IperfConnectError as e:
                raise IperfConnectError(f"{e}. Server log: {tail_text(read_text(server_log), 3)}")
            except ParseError as e:
                raise StepFailed(step, f"{e}. Server log: {tail_text(read_text(server_log), 3)}")
            if p.returncode != 0:
                raise StepFailed(step, f"iperf3 exit code {p.returncode}: {tail_text(p.stderr)}")
            return mbps
        finally:
            self.stop_child(server)

    def stop_child(self, proc, wait=5):
        try:
            proc.wait(timeout=wait)          # a good run: the one-off server ends by itself
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait()
        if proc in self.children:
            self.children.remove(proc)

    # --- the loop ---
    def run_all(self):
        s = self.settings
        os.makedirs(self.raw, exist_ok=True)
        total = len(self.modes) * len(self.conditions) * s["runs"]
        self.say(f"Plan: {len(self.modes)} modes x {len(self.conditions)} conditions x {s['runs']} runs = {total} runs")
        self.say(f"Estimated time: about {fmt_duration(estimate_seconds(s, len(self.modes), len(self.conditions)))} "
                 f"(a guess, the real pace is shown below)")
        self.say(f"Results go to {os.path.relpath(self.out, os.getcwd())}/")
        self.started = time.time()
        done = 0
        with open(self.partial_path, "w", newline="") as pf:
            writer = csv.writer(pf)
            writer.writerow(CSV_COLUMNS)
            self.set_netem_off("start")
            for mode in self.modes:
                self.say(f"\n== mode {mode}: switching ==")
                target = self.switch_mode(mode)
                self.say(f"   target {target}")
                for cond in self.conditions:
                    self.set_netem(cond)
                    for run in range(1, s["runs"] + 1):
                        tag = f"{mode}-{cond}-{run}"
                        run_started = time.time()
                        self.warm_up(target, tag)
                        ping = self.measure_ping(target, tag)
                        time.sleep(SETTLE_SECONDS)
                        mbps = self.measure_iperf3(target, tag, f"{mode} {cond} run {run}")
                        row = {"protocol": PROTOCOLS[mode], "condition": cond, "run": run,
                               "throughput_mbps": mbps, "rtt_ms": ping["rtt_avg_ms"], "loss_pct": ping["loss_pct"]}
                        self.rows.append(row)
                        self.details.append((row, ping["stats"]))
                        writer.writerow(csv_row(row))
                        pf.flush()
                        done += 1
                        slow = slow_run_note(time.time() - run_started, expected_run_seconds(s))
                        if slow:
                            self.notes.append(f"{mode} {cond} run {run}: {slow}")
                        elapsed = time.time() - self.started
                        left = elapsed / done * (total - done)
                        self.say(f"[{done}/{total}] {mode} {cond} run {run}: {mbps:.1f} Mbit/s, "
                                 f"RTT {ping['rtt_avg_ms']:.1f} ms, loss {ping['loss_pct']:.0f}%   "
                                 f"(elapsed {fmt_duration(elapsed)}, about {fmt_duration(left)} left)")
                        if slow:
                            self.say(f"   WARNING {slow}")
                    self.set_netem_off(f"end of {mode} {cond}")
        os.replace(self.partial_path, os.path.join(self.out, "summary.csv"))

    def set_netem_off(self, why):
        self.sh(f"remove the network condition (netem.sh off, {why})", [NETEM, "off"], 30)

    # --- cleanup: always runs, also after a failure or Ctrl+C ---
    def cleanup(self):
        for proc in list(self.children):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait()
        self.children.clear()
        results = []
        for label, argv in (("switch.py off", [sys.executable, SWITCH, "off"]), ("netem.sh off", [NETEM, "off"])):
            try:
                p = subprocess.run(argv, capture_output=True, text=True, timeout=SWITCH_TIMEOUT)
                results.append(f"{label}: " + ("ok" if p.returncode == 0 else f"FAILED ({tail_text(p.stdout + p.stderr, 2)})"))
            except (OSError, subprocess.TimeoutExpired) as e:
                results.append(f"{label}: FAILED ({e})")
        self.say("Cleanup: " + "; ".join(results))
        if any("FAILED" in r for r in results):
            self.say("Run by hand: sudo python3 lab/switch.py off  and  sudo ./lab/netem.sh off")


# ---------- environment.txt and ownership ----------

def first_line(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return "not found"
    lines = (p.stdout + p.stderr).strip().splitlines()
    return lines[0].strip() if lines else "no output"


def netem_presets():
    """The three preset lines from lab/netem.sh, copied as they are (so the report shows what was used)."""
    try:
        text = open(NETEM).read()
    except OSError:
        return ["(could not read lab/netem.sh)"]
    return [m.group(0).strip() for m in re.finditer(r"^\s*(good|normal|bad)\)\s+OPTS=\"[^\"]*\"", text, re.M)]


def git_commit():
    out = first_line(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"])
    dirty = subprocess.run(["git", "-C", ROOT, "status", "--porcelain"], capture_output=True, text=True).stdout.strip()
    return out + (" (with uncommitted changes)" if dirty else "")


def environment_text(settings, modes, conditions, started, finished):
    lines = [
        f"date (start):    {datetime.datetime.fromtimestamp(started).astimezone().isoformat(timespec='seconds')}",
        f"date (end):      {datetime.datetime.fromtimestamp(finished).astimezone().isoformat(timespec='seconds')}",
        f"duration:        {fmt_duration(finished - started)}",
        f"kernel:          {platform.release()}",
        f"os:              {first_line(['lsb_release', '-ds'])}",
        f"iperf3:          {first_line(['iperf3', '--version'])}",
        f"wireguard-tools: {first_line(['wg', '--version'])}",
        f"openvpn:         {first_line(['openvpn', '--version'])}",
        f"python:          {sys.version.split()[0]}",
        f"git commit:      {git_commit()}",
        "",
        f"modes:           {', '.join(modes)}",
        f"conditions:      {', '.join(conditions)}",
        f"runs per cell:   {settings['runs']}",
        f"iperf3:          TCP, {settings['iperf_seconds']} s, client1 -> serverA target address, receiver-side Mbit/s",
        f"ping:            {settings['ping_count']} packets, interval {settings['ping_interval']} s, mean RTT per run",
        "warm-up:         3 pings (up to 3 tries) before every run",
        "netem presets (lab/netem.sh, applied on eth1 of router1 and router2, both directions):",
    ] + ["    " + p for p in netem_presets()] + ["    none)   no netem (netem.sh off): the lab link as it is"]
    return "\n".join(lines) + "\n"


def give_back_ownership(top):
    """We run as root through sudo. Hand the results to the person who ran sudo, so they can edit and commit."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid or not gid:
        return
    try:
        os.chown(top, int(uid), int(gid))
        for dirpath, dirs, files in os.walk(top):
            for name in dirs + files:
                os.chown(os.path.join(dirpath, name), int(uid), int(gid))
    except OSError as e:
        print(f"warning: could not change the owner of {top}: {e}")


# ---------- command line ----------

def parse_args(argv):
    ap = argparse.ArgumentParser(prog="run_experiments.py", description="Run all measurements. Needs sudo.")
    ap.add_argument("--modes", nargs="+", choices=list(PROTOCOLS), default=list(PROTOCOLS), metavar="MODE",
                    help="modes to measure (default: all of %s)" % " ".join(PROTOCOLS))
    ap.add_argument("--conditions", nargs="+", choices=CONDITIONS, default=CONDITIONS, metavar="COND",
                    help="network conditions (default: none good normal bad; none = no netem)")
    ap.add_argument("--runs", type=int, default=None, help="runs per mode and condition (default 3; 1 with --quick)")
    ap.add_argument("--iperf-seconds", type=int, default=None, metavar="N",
                    help="length of each iperf3 test in seconds (default 10; 3 with --quick)")
    ap.add_argument("--quick", action="store_true",
                    help="1 run, iperf3 for 3 s, 10 pings (only checks the pipeline: 3 s is too short for Bad). "
                         "Writes to results/quick/ so real results are kept")
    ap.add_argument("--out", default=None, help="output folder (default results/, or results/quick/ with --quick)")
    args = ap.parse_args(argv)
    if args.runs is not None and args.runs < 1:
        ap.error("--runs must be 1 or more")
    # keep the fixed order (and no duplicates) whatever order the user typed
    args.modes = [m for m in PROTOCOLS if m in args.modes]
    args.conditions = [c for c in CONDITIONS if c in args.conditions]
    if args.iperf_seconds is not None and args.iperf_seconds < 1:
        ap.error("--iperf-seconds must be 1 or more")
    args.runs = args.runs or (1 if args.quick else 3)
    args.settings = {"runs": args.runs, "iperf_seconds": args.iperf_seconds or (3 if args.quick else 10),
                     "ping_count": 10 if args.quick else 100, "ping_interval": 0.2}
    args.out = os.path.abspath(args.out) if args.out else os.path.join(RESULTS, "quick") if args.quick else RESULTS
    return args


def _stop(signum, frame):
    raise KeyboardInterrupt


def main(argv=None):
    args = parse_args(argv)
    if os.geteuid() != 0:
        print("Run with sudo")
        return 1
    missing = [t for t in ("ip", "ping", "iperf3") if shutil.which(t) is None]
    if missing:
        print("Missing programs: " + ", ".join(missing))
        return 1
    signal.signal(signal.SIGTERM, _stop)
    exp = Experiment(args.modes, args.conditions, args.settings, args.out)
    rc = 0
    try:
        exp.run_all()
        finished = time.time()
        write_text(os.path.join(args.out, "table.md"), make_table_md(exp.rows, args.settings, exp.details))
        write_detail_csv(os.path.join(args.out, "rtt_detail.csv"), exp.details)
        write_text(os.path.join(args.out, "notes.txt"),
                   "\n".join(exp.notes) + "\n" if exp.notes else "No retries, zero-throughput runs or slow runs.\n")
        write_text(os.path.join(args.out, "environment.txt"),
                   environment_text(args.settings, args.modes, args.conditions, exp.started, finished))
        print(f"\nDone in {fmt_duration(finished - exp.started)}. Wrote summary.csv, rtt_detail.csv, table.md, notes.txt, environment.txt in {args.out}")
    except StepFailed as e:
        print(f"\nFAILED at step: {e.step}")
        if e.detail:
            print(f"  {e.detail}")
        if exp.notes:
            print("Notes so far:\n  " + "\n  ".join(exp.notes))
        print(f"Raw files so far: {exp.raw}   Rows measured so far: {exp.partial_path}")
        rc = 1
    except KeyboardInterrupt:
        print("\nInterrupted. Cleaning up.")
        rc = 130
    finally:
        exp.cleanup()
        top = RESULTS if args.out == RESULTS or args.out.startswith(RESULTS + os.sep) else args.out
        if os.path.isdir(top):
            give_back_ownership(top)
    return rc


if __name__ == "__main__":
    sys.exit(main())
