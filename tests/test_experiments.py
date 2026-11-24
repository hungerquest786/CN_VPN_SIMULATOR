"""Tests for lab/run_experiments.py: parsing, statistics, CSV and table. No root needed.

tests/data/iperf3_real.json and ping_real.txt are REAL outputs (iperf3 3.20 and ping on loopback).
The ping samples with loss are written by hand in the same format.
"""
import csv
import math
import os
import re
import statistics
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "lab"))
sys.path.insert(0, ROOT)
import run_experiments as rx
import switch
from dashboard.results import read_results

DATA = os.path.join(HERE, "data")


def data(name):
    with open(os.path.join(DATA, name)) as f:
        return f.read()


# ---- iperf3 ----

def test_iperf3_real_output():
    import json
    text = data("iperf3_real.json")
    expected = json.loads(text)["end"]["sum_received"]["bits_per_second"] / 1e6
    assert rx.parse_iperf3_json(text) == pytest.approx(expected)
    assert expected > 1


def test_iperf3_error_json_is_a_connect_error():
    text = '{"start": {}, "intervals": [], "end": {}, "error": "unable to connect: Connection refused"}'
    with pytest.raises(rx.IperfConnectError, match="Connection refused"):
        rx.parse_iperf3_json(text)


def test_iperf3_no_connected_stream_is_a_connect_error():
    with pytest.raises(rx.IperfConnectError, match="never connected"):
        rx.parse_iperf3_json('{"start": {"connected": []}, "end": {"sum_received": {"bits_per_second": 5}}}')


@pytest.mark.parametrize("text", ["", "not json", "[1, 2]", '{"start": {"connected": [1]}, "end": {}}',
                                  '{"start": {"connected": [1]}, "end": {"sum_received": {}}}'])
def test_iperf3_bad_input(text):
    with pytest.raises(rx.ParseError) as info:
        rx.parse_iperf3_json(text)
    assert not isinstance(info.value, rx.IperfConnectError)       # not worth a retry


def test_iperf3_connected_but_nothing_arrived_is_zero_not_an_error():
    """Real case from the quick run: WireGuard / bad, 3 s, sender wrote one block, receiver got 0 bytes."""
    import json
    d = json.loads(data("iperf3_real.json"))
    d["end"]["sum_received"].update(bytes=0, bits_per_second=0)
    assert rx.parse_iperf3_json(json.dumps(d)) == 0.0


# ---- retry and notes (the logic around one iperf3 attempt; the attempt itself needs root) ----

def make_exp(tmp_path):
    exp = rx.Experiment(["plain"], ["good"], {"runs": 1, "iperf_seconds": 3, "ping_count": 10, "ping_interval": 0.2},
                        str(tmp_path), say=lambda *_: None)
    os.makedirs(exp.raw)
    return exp


def fake_attempts(exp, results):
    """Replace the real attempt: each call returns the next item, or raises it if it is an exception."""
    calls = []

    def attempt(target, tag, step):
        calls.append(tag)
        r = results[len(calls) - 1]
        if isinstance(r, Exception):
            raise r
        return r
    exp.iperf3_attempt = attempt
    return calls


def test_zero_throughput_is_recorded_with_a_note_and_no_retry(tmp_path):
    exp = make_exp(tmp_path)
    calls = fake_attempts(exp, [0.0])
    assert exp.measure_iperf3("10.9.0.1", "wireguard-bad-1", "wireguard bad run 1") == 0.0
    assert len(calls) == 1
    assert len(exp.notes) == 1 and "wireguard bad run 1" in exp.notes[0] and "0 bytes" in exp.notes[0]


def test_connect_error_is_retried_once_and_noted(tmp_path):
    exp = make_exp(tmp_path)
    (tmp_path / "raw" / "plain-good-1.iperf3.json").write_text("first")
    (tmp_path / "raw" / "plain-good-1.iperf3-server.log").write_text("first log")
    calls = fake_attempts(exp, [rx.IperfConnectError("Connection refused"), 12.5])
    assert exp.measure_iperf3("10.0.3.2", "plain-good-1", "plain good run 1") == 12.5
    assert len(calls) == 2
    assert "retry worked" in exp.notes[0] and "Connection refused" in exp.notes[0]
    assert (tmp_path / "raw" / "plain-good-1.iperf3.attempt1.json").read_text() == "first"
    assert (tmp_path / "raw" / "plain-good-1.iperf3-server.attempt1.log").read_text() == "first log"
    assert not (tmp_path / "raw" / "plain-good-1.iperf3.json").exists()


def test_two_connect_errors_stop_the_run(tmp_path):
    exp = make_exp(tmp_path)
    calls = fake_attempts(exp, [rx.IperfConnectError("a"), rx.IperfConnectError("b"), 99.0])
    with pytest.raises(rx.StepFailed) as info:
        exp.measure_iperf3("10.0.3.2", "plain-good-1")
    assert len(calls) == 2 and "twice" in info.value.detail


def test_other_parse_problems_are_not_retried(tmp_path):
    exp = make_exp(tmp_path)
    calls = fake_attempts(exp, [rx.ParseError("not JSON"), 5.0])
    with pytest.raises(rx.StepFailed):
        exp.measure_iperf3("10.0.3.2", "plain-good-1")
    assert len(calls) == 1


# ---- ping ----

def test_ping_real_output():
    r = rx.parse_ping(data("ping_real.txt"))
    assert (r["sent"], r["received"], r["loss_pct"]) == (5, 5, 0.0)
    assert r["rtt_avg_ms"] == pytest.approx(0.027)
    assert r["rtt_min_ms"] == pytest.approx(0.022) and r["rtt_max_ms"] == pytest.approx(0.045)


def test_ping_with_loss_by_hand():
    text = ("--- 10.0.3.2 ping statistics ---\n"
            "100 packets transmitted, 94 received, 6% packet loss, time 20180ms\n"
            "rtt min/avg/max/mdev = 100.123/105.456/603.789/40.123 ms\n")
    r = rx.parse_ping(text)
    assert r["loss_pct"] == pytest.approx(6.0)
    assert r["rtt_avg_ms"] == pytest.approx(105.456)
    assert r["rtt_mdev_ms"] == pytest.approx(40.123)


def test_ping_loss_uses_the_counts_not_the_rounded_percent():
    text = ("3 packets transmitted, 2 received, 33% packet loss, time 400ms\n"
            "rtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms\n")
    assert rx.parse_ping(text)["loss_pct"] == pytest.approx(100 / 3)


def test_ping_with_errors_and_duplicates_still_parses():
    text = ("10 packets transmitted, 9 received, +1 errors, 10% packet loss, time 1800ms\n"
            "rtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms\n")
    assert rx.parse_ping(text)["loss_pct"] == pytest.approx(10.0)
    text = ("10 packets transmitted, 10 received, +2 duplicates, 0% packet loss, time 1800ms\n"
            "rtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms\n")
    assert rx.parse_ping(text)["loss_pct"] == 0.0


def test_ping_times_from_real_output_and_dup_lines():
    assert rx.parse_ping_times(data("ping_real.txt")) == [0.022, 0.022, 0.025, 0.045, 0.023]
    text = ("64 bytes from 10.0.3.2: icmp_seq=1 ttl=64 time=21.5 ms\n"
            "64 bytes from 10.0.3.2: icmp_seq=1 ttl=64 time=22.0 ms (DUP!)\n"
            "64 bytes from 10.0.3.2: icmp_seq=2 ttl=64 time=130 ms\n")
    assert rx.parse_ping_times(text) == [21.5, 130.0]
    assert rx.parse_ping_times("no replies here") == []


def test_rtt_stats_with_spikes():
    # the Plain/good quick run: two slow replies pull the mean far above the median
    times = [22, 25, 26, 26, 34, 35, 89, 93, 108, 109]
    s = rx.rtt_stats(times)
    assert (s["rtt_min_ms"], s["rtt_max_ms"], s["replies_over_100ms"]) == (22, 109, 2)
    assert s["rtt_median_ms"] == pytest.approx(34.5)
    assert s["rtt_p95_ms"] == 109                         # nearest rank: ceil(0.95 * 10) = 10th value
    assert statistics.mean(times) > 50 > s["rtt_median_ms"]


def test_rtt_stats_p95_nearest_rank_and_single_value():
    assert rx.rtt_stats(list(range(1, 101)))["rtt_p95_ms"] == 95
    assert rx.rtt_stats([7.0]) == {"rtt_min_ms": 7.0, "rtt_median_ms": 7.0, "rtt_p95_ms": 7.0,
                                   "rtt_max_ms": 7.0, "replies_over_100ms": 0}
    with pytest.raises(ValueError):
        rx.rtt_stats([])


def test_ping_all_lost_has_no_rtt():
    r = rx.parse_ping("3 packets transmitted, 0 received, 100% packet loss, time 415ms\n")
    assert r["received"] == 0 and r["loss_pct"] == 100.0 and r["rtt_avg_ms"] is None


@pytest.mark.parametrize("text", ["", "ping: connect: Network is unreachable",
                                  "5 packets transmitted, 5 received, 0% packet loss\n"])  # replies but no rtt line
def test_ping_bad_input(text):
    with pytest.raises(rx.ParseError):
        rx.parse_ping(text)


# ---- mean and standard deviation ----

def test_mean_sd_known_values():
    assert rx.mean_sd([1, 2, 3]) == (2.0, 1.0)
    mean, sd = rx.mean_sd([2, 4, 4, 4, 5, 5, 7, 9])
    assert mean == 5.0
    assert sd == pytest.approx(math.sqrt(32 / 7))            # sample SD: divide by n-1
    assert sd == pytest.approx(statistics.stdev([2, 4, 4, 4, 5, 5, 7, 9]))


def test_mean_sd_one_value_and_empty():
    assert rx.mean_sd([7.5]) == (7.5, 0.0)
    with pytest.raises(ValueError):
        rx.mean_sd([])


def row(p, c, run, t, r, l):
    return {"protocol": p, "condition": c, "run": run, "throughput_mbps": t, "rtt_ms": r, "loss_pct": l}


ROWS = [row("Plain", "good", 1, 90.0, 20.0, 0.0), row("Plain", "good", 2, 100.0, 22.0, 1.0),
        row("Plain", "good", 3, 110.0, 24.0, 2.0), row("GRE", "good", 1, 80.0, 21.0, 0.0)]


def test_summarise_groups_in_first_seen_order():
    s = rx.summarise(ROWS)
    assert list(s) == [("Plain", "good"), ("GRE", "good")]
    assert s[("Plain", "good")]["runs"] == 3
    assert s[("Plain", "good")]["throughput_mbps"] == (100.0, 10.0)
    assert s[("Plain", "good")]["loss_pct"] == (1.0, 1.0)
    assert s[("GRE", "good")]["rtt_ms"] == (21.0, 0.0)       # one run: SD 0


# ---- CSV and table ----

def test_csv_header_and_names_match_the_fake_file(tmp_path):
    path = tmp_path / "summary.csv"
    rx.write_summary_csv(str(path), ROWS)
    with open(os.path.join(HERE, "fake_summary.csv")) as f:
        fake_header = f.readline().strip()
    assert path.read_text().splitlines()[0] == fake_header == ",".join(rx.CSV_COLUMNS)
    with open(os.path.join(HERE, "fake_summary.csv"), newline="") as f:
        fake = list(csv.DictReader(f))
    assert {(r["protocol"], r["condition"]) for r in fake} == \
           {(p, c) for p in rx.PROTOCOLS.values() for c in rx.CONDITIONS if c != "none"}   # fake file: 3 conditions
    assert list(dict.fromkeys(r["protocol"] for r in fake)) == list(rx.PROTOCOLS.values())   # same order


def test_dashboard_reads_our_csv(tmp_path):
    path = tmp_path / "summary.csv"
    rx.write_summary_csv(str(path), ROWS)
    res = read_results(str(path))
    assert res["available"] and res["protocols"] == ["Plain", "GRE"]
    plain = next(e for e in res["stats"] if e["protocol"] == "Plain")
    assert plain["runs"] == 3 and plain["throughput_mbps"]["mean"] == pytest.approx(100.0)
    assert plain["throughput_mbps"]["std"] == pytest.approx(10.0)


DETAILS = [(ROWS[0], rx.rtt_stats([20, 22, 150])), (ROWS[1], rx.rtt_stats([21, 23, 25])),
           (ROWS[2], rx.rtt_stats([22, 24, 200])), (ROWS[3], rx.rtt_stats([30, 31, 32]))]


def test_table_md_has_median_and_minimum_with_details():
    md = rx.make_table_md(ROWS, {"iperf_seconds": 10, "ping_count": 100, "ping_interval": 0.2}, DETAILS)
    assert md.count("## ") == 5
    assert md.index("## Mean RTT") < md.index("## Median RTT") < md.index("## Minimum RTT") < md.index("## Packet loss")
    # Plain good: medians 22, 23, 24 -> 23.0 ± 1.0 ; minimums 20, 21, 22 -> 21.0 ± 1.0 ; GRE one run -> SD 0
    assert "| Plain | 23.0 ± 1.0 |" in md and "| Plain | 21.0 ± 1.0 |" in md
    assert "| GRE | 31.0 ± 0.0 |" in md and "| GRE | 30.0 ± 0.0 |" in md


def test_detail_csv(tmp_path):
    path = tmp_path / "rtt_detail.csv"
    rx.write_detail_csv(str(path), DETAILS)
    rows = list(csv.DictReader(open(path)))
    assert list(rows[0]) == rx.DETAIL_COLUMNS and len(rows) == 4
    assert rows[0]["protocol"] == "Plain" and rows[0]["run"] == "1"
    assert float(rows[0]["rtt_median_ms"]) == 22 and float(rows[0]["rtt_max_ms"]) == 150
    assert rows[0]["replies_over_100ms"] == "1"
    # same protocol/condition/run keys as the main CSV rows
    assert [(r["protocol"], r["condition"], r["run"]) for r in rows] == \
           [(r["protocol"], r["condition"], str(r["run"])) for r in ROWS]


def test_table_md_notes_zero_runs():
    rows = ROWS + [row("GRE", "bad", 1, 0.0, 300.0, 5.0), row("GRE", "bad", 2, 2.0, 310.0, 5.0)]
    md = rx.make_table_md(rows, {"iperf_seconds": 10, "ping_count": 100, "ping_interval": 0.2})
    assert "- GRE / bad: 1 of 2 runs connected but received 0 bytes" in md
    assert "| GRE | 80.00 ± 0.00 | 1.00 ± 1.41 |" in md


def test_table_md():
    md = rx.make_table_md(ROWS, {"iperf_seconds": 10, "ping_count": 100, "ping_interval": 0.2})
    assert "| Plain | 100.00 ± 10.00 |" in md
    assert "| GRE | 80.00 ± 0.00 |" in md
    assert md.count("## ") == 3 and "sample standard deviation" in md


# ---- names, arguments, estimate ----

def test_modes_and_conditions_match_the_other_scripts():
    assert set(rx.PROTOCOLS) == set(switch.MODES)
    with open(os.path.join(ROOT, "lab", "netem.sh")) as f:
        presets = re.findall(r"^\s+(good|normal|bad)\)\s+OPTS=", f.read(), re.M)
    assert presets == [c for c in rx.CONDITIONS if c != "none"]     # every netem preset is measured, unchanged


def test_args_default_and_quick():
    a = rx.parse_args([])
    assert a.modes == list(rx.PROTOCOLS) and a.conditions == rx.CONDITIONS
    assert a.settings == {"runs": 3, "iperf_seconds": 10, "ping_count": 100, "ping_interval": 0.2}
    assert a.out == rx.RESULTS
    q = rx.parse_args(["--quick"])
    assert q.settings == {"runs": 1, "iperf_seconds": 3, "ping_count": 10, "ping_interval": 0.2}
    assert q.out == os.path.join(rx.RESULTS, "quick")


def test_iperf_seconds_option():
    assert rx.parse_args(["--iperf-seconds", "7"]).settings["iperf_seconds"] == 7
    assert rx.parse_args(["--quick"]).settings["iperf_seconds"] == 3
    assert rx.parse_args(["--quick", "--iperf-seconds", "10"]).settings["iperf_seconds"] == 10   # explicit wins
    assert rx.parse_args([]).settings["iperf_seconds"] == 10
    with pytest.raises(SystemExit):
        rx.parse_args(["--iperf-seconds", "0"])


def test_args_fixed_order_and_errors():
    a = rx.parse_args(["--modes", "gre", "plain", "--conditions", "bad", "good", "--runs", "2"])
    assert a.modes == ["plain", "gre"] and a.conditions == ["good", "bad"] and a.settings["runs"] == 2
    with pytest.raises(SystemExit):
        rx.parse_args(["--modes", "ipsec"])
    with pytest.raises(SystemExit):
        rx.parse_args(["--runs", "0"])


def test_estimate_grows_with_work():
    full = {"runs": 3, "iperf_seconds": 10, "ping_count": 100, "ping_interval": 0.2}
    quick = {"runs": 1, "iperf_seconds": 3, "ping_count": 10, "ping_interval": 0.2}
    assert rx.estimate_seconds(quick, 5, 3) < rx.estimate_seconds(full, 5, 3)
    assert 20 * 60 < rx.estimate_seconds(full, 5, 3) < 45 * 60
    assert rx.fmt_duration(125) == "2 min 05 s" and rx.fmt_duration(9) == "9 s"


# ---- stall detection (a paused VM wakes up with the clock far ahead) ----

def test_stall_message():
    assert rx.stall_message(50.5, 50) is None                 # a normal timeout: just 50 s passed
    assert rx.stall_message(149, 50) is None                  # up to 3x the limit is not called a stall
    msg = rx.stall_message(6235, 50)                          # the real incident: 1 h 44 min on a 50 s limit
    assert "103 min 55 s" in msg and "50 s" in msg and "paused" in msg and "run again" in msg


def test_timeout_detail_adds_the_stall_text_only_when_the_clock_jumped(monkeypatch):
    clock = iter([1000.0, 1050.0, 1000.0, 7235.0])
    fake = type("T", (), {"time": staticmethod(lambda: next(clock)), "sleep": staticmethod(lambda s: None)})
    monkeypatch.setattr(rx, "time", fake)
    normal = rx.timeout_detail(50, fake.time(), "ping x")       # started 1000, now 1050
    assert normal == "no answer after 50 s: ping x"
    stalled = rx.timeout_detail(50, fake.time(), "ping x")      # started 1000, now 7235
    assert "VM was probably paused" in stalled and "no answer after 50 s: ping x" in stalled


def test_slow_run_note():
    s = {"runs": 3, "iperf_seconds": 10, "ping_count": 100, "ping_interval": 0.2}
    expected = rx.expected_run_seconds(s)
    assert 30 < expected < 50
    assert rx.slow_run_note(expected * 1.5, expected) is None   # slow but normal (Bad runs took 1.5x)
    note = rx.slow_run_note(expected * 3, expected)
    assert note and "slow run" in note and "paused" in note


def test_estimate_uses_the_same_run_time():
    s = {"runs": 2, "iperf_seconds": 10, "ping_count": 100, "ping_interval": 0.2}
    assert rx.estimate_seconds(s, 1, 1) == 15.0 + 1.0 + 2 * rx.expected_run_seconds(s)


def test_sh_timeout_keeps_partial_output_and_names_the_step(tmp_path):
    exp = make_exp(tmp_path)
    log = str(tmp_path / "raw" / "t.txt")
    with pytest.raises(rx.StepFailed) as info:
        exp.sh("slow step", ["sh", "-c", "echo partial; exec sleep 5"], 0.5, log=log)
    assert info.value.step == "slow step"
    assert info.value.detail.startswith("no answer after 0.5 s")      # a real, short timeout is no stall
    text = open(log).read()
    assert "partial" in text and "timed out" in text


def test_sh_timeout_after_a_clock_jump_says_so(tmp_path, monkeypatch):
    exp = make_exp(tmp_path)
    clock = iter([1000.0, 7235.0])
    fake = type("T", (), {"time": staticmethod(lambda: next(clock)), "sleep": staticmethod(lambda s: None)})

    def boom(argv, **kw):
        raise rx.subprocess.TimeoutExpired(argv, kw["timeout"])
    monkeypatch.setattr(rx, "time", fake)
    monkeypatch.setattr(rx.subprocess, "run", boom)
    with pytest.raises(rx.StepFailed) as info:
        exp.sh("ping x", ["ping", "x"], 50, log=str(tmp_path / "raw" / "p.txt"))
    assert "VM was probably paused" in info.value.detail
    assert "timed out" in open(tmp_path / "raw" / "p.txt").read()


# ---- the "none" condition (no netem) ----

def test_none_is_first_and_maps_to_netem_off():
    assert rx.CONDITIONS[0] == "none" and rx.CONDITIONS[1:] == ["good", "normal", "bad"]
    assert rx.NETEM_ARG == {"none": "off"}
    a = rx.parse_args([])
    assert a.conditions[0] == "none" and len(a.conditions) == 4
    assert rx.parse_args(["--conditions", "bad", "none"]).conditions == ["none", "bad"]      # fixed order


def test_set_netem_gives_netem_sh_the_right_word(tmp_path):
    exp = make_exp(tmp_path)
    calls = []
    exp.sh = lambda step, argv, timeout, log=None: calls.append((step, argv))
    for cond in ("none", "good", "bad"):
        exp.set_netem(cond)
    assert [argv for _, argv in calls] == [[rx.NETEM, "off"], [rx.NETEM, "good"], [rx.NETEM, "bad"]]
    assert "'none'" in calls[0][0] and "netem.sh off" in calls[0][0]


def test_table_and_dashboard_take_none_first(tmp_path):
    rows = [row("Plain", "none", 1, 900.0, 0.4, 0.0), row("Plain", "good", 1, 80.0, 21.0, 0.0),
            row("GRE", "none", 1, 800.0, 0.5, 0.0), row("GRE", "good", 1, 70.0, 22.0, 0.0)]
    md = rx.make_table_md(rows, {"iperf_seconds": 10, "ping_count": 100, "ping_interval": 0.2})
    assert "| Protocol | none | good |" in md and "| Plain | 900.00 ± 0.00 | 80.00 ± 0.00 |" in md
    path = tmp_path / "summary.csv"
    rx.write_summary_csv(str(path), rows)
    assert read_results(str(path))["conditions"] == ["none", "good"]


def test_results_js_describes_every_condition():
    js = open(os.path.join(ROOT, "dashboard", "static", "results.js")).read()
    for c in rx.CONDITIONS:
        assert re.search(rf"^\s+{c}:\s*\"", js, re.M), c
    assert 'none: "no impairment (netem off)"' in js
