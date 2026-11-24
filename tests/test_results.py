import math
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from dashboard.results import ResultsError, mean_std, read_results

HEADER = "protocol,condition,run,throughput_mbps,rtt_ms,loss_pct\n"


def write(tmp_path, text):
    p = tmp_path / "summary.csv"
    p.write_text(text)
    return str(p)


def test_missing_file_means_no_results_yet(tmp_path):
    assert read_results(str(tmp_path / "nope.csv")) == {"available": False}


def test_header_only_file_means_no_results_yet(tmp_path):
    assert read_results(write(tmp_path, HEADER)) == {"available": False}


def test_mean_and_sample_standard_deviation():
    mean, std = mean_std([2.0, 4.0, 6.0])
    assert mean == 4.0 and math.isclose(std, 2.0)        # sqrt(((-2)^2 + 0 + 2^2) / 2)
    assert mean_std([5.0]) == (5.0, 0.0)                 # one run: no spread


def test_reads_groups_and_keeps_file_order(tmp_path):
    r = read_results(write(tmp_path, HEADER +
        "Plain,good,1,900,0.4,0\nPlain,good,2,940,0.5,0\nMini VPN,good,1,400,0.9,0.1\nPlain,bad,1,4.8,152,5.1\n"))
    assert r["available"] and r["protocols"] == ["Plain", "Mini VPN"] and r["conditions"] == ["good", "bad"]
    assert r["max_runs"] == 2
    plain_good = next(s for s in r["stats"] if s["protocol"] == "Plain" and s["condition"] == "good")
    assert plain_good["runs"] == 2
    assert plain_good["throughput_mbps"]["mean"] == 920.0
    assert math.isclose(plain_good["throughput_mbps"]["std"], math.sqrt(800))
    assert plain_good["loss_pct"] == {"mean": 0.0, "std": 0.0}


def test_missing_column_is_a_clear_error(tmp_path):
    with pytest.raises(ResultsError, match="rtt_ms"):
        read_results(write(tmp_path, "protocol,condition,run,throughput_mbps,loss_pct\nPlain,good,1,9,0\n"))


def test_non_number_is_a_clear_error_with_line_number(tmp_path):
    with pytest.raises(ResultsError, match="line 3"):
        read_results(write(tmp_path, HEADER + "Plain,good,1,9,0.4,0\nPlain,good,2,abc,0.4,0\n"))


def test_the_fake_preview_file_loads():
    r = read_results(os.path.join(HERE, "fake_summary.csv"))
    assert len(r["protocols"]) == 5 and r["conditions"] == ["good", "normal", "bad"] and r["max_runs"] == 3
