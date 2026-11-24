import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common.login import Sessions
from common.serverstats import MAX_EVENTS, ServerStats, write_stats


def test_write_stats_makes_valid_json_and_leaves_no_temp_file(tmp_path):
    path = tmp_path / "stats.json"
    write_stats(str(path), {"a": 1})
    write_stats(str(path), {"a": 2})                 # second write replaces the first
    assert json.loads(path.read_text()) == {"a": 2}
    assert os.listdir(tmp_path) == ["stats.json"]    # the temp file was renamed away
    assert (path.stat().st_mode & 0o777) == 0o644    # the dashboard may run as another user


def test_failed_write_keeps_old_file_and_cleans_up(tmp_path):
    path = tmp_path / "stats.json"
    write_stats(str(path), {"ok": True})
    with pytest.raises(TypeError):
        write_stats(str(path), {"bad": object()})    # cannot be turned into JSON
    assert json.loads(path.read_text()) == {"ok": True}
    assert os.listdir(tmp_path) == ["stats.json"]


def make_session(sessions, user="alice", sid=1):
    return sessions.add(user, sid, b"c" * 32, b"s" * 32)


def test_snapshot_has_everything_the_dashboard_needs():
    st, sessions = ServerStats(), Sessions()
    s = make_session(sessions)
    s.addr, s.bytes_in, s.bytes_out = ("10.0.1.2", 5555), 1000, 2000
    st.handshake_done()
    st.login_ok("alice", s.ip)
    snap = st.snapshot(sessions.all(), now=s.connected_at + 90)
    c = snap["clients"][0]
    assert c == {"name": "alice", "tunnel_ip": "10.8.0.2", "real_address": "10.0.1.2", "bytes_in": 1000,
                 "bytes_out": 2000, "key_epoch": 0, "connected_seconds": 90}
    assert snap["counters"] == {"handshakes": 1, "refused_logins": 0, "rekeys": 0, "replay_drops": 0, "wrong_source_drops": 0}
    assert snap["server_time"] == s.connected_at + 90
    assert len(snap["throughput_mbps"]) == 60
    assert snap["events"][0]["type"] == "login ok"
    json.dumps(snap)                                  # must be plain JSON data


def test_client_without_udp_packet_yet_has_no_real_address():
    st, sessions = ServerStats(), Sessions()
    make_session(sessions)
    assert st.snapshot(sessions.all())["clients"][0]["real_address"] is None


def test_counters_and_event_details():
    st = ServerStats()
    st.login_refused("10.0.1.9")
    st.rekeyed("carol", 5)
    st.replay_dropped("bob", 43754)
    st.wrong_source_dropped("alice", "10.0.1.5")
    snap = st.snapshot([])
    assert snap["counters"] == {"handshakes": 0, "refused_logins": 1, "rekeys": 1, "replay_drops": 1, "wrong_source_drops": 1}
    got = [(e["type"], e["client"], e["detail"]) for e in snap["events"]]    # newest first
    assert got == [("wrong source dropped", "alice", "src 10.0.1.5"), ("replay dropped", "bob", "seq 43754"),
                   ("rekeyed", "carol", "epoch 5"), ("login refused", "", "from 10.0.1.9")]


def test_only_the_last_20_events_are_kept():
    st = ServerStats()
    for i in range(MAX_EVENTS + 5):
        st.rekeyed("alice", i)
    events = st.snapshot([])["events"]
    assert len(events) == MAX_EVENTS
    assert events[0]["detail"] == f"epoch {MAX_EVENTS + 4}"          # newest first


def test_a_flood_of_the_same_drop_is_counted_but_listed_once_per_second():
    st = ServerStats()
    for i in range(100):
        st.replay_dropped("bob", i)                                  # all in the same instant
    snap = st.snapshot([])
    assert snap["counters"]["replay_drops"] == 100
    assert len(snap["events"]) == 1


def test_throughput_last_60_seconds_in_mbit_per_second():
    st = ServerStats()
    st.add_bytes(1_250_000, now=1000.2)              # 1.25 MB in second 1000 = 10 Mbit/s
    st.add_bytes(1_250_000, now=1000.9)              # same second: adds up to 20 Mbit/s
    st.add_bytes(125_000, now=1005.5)                # 1 Mbit/s
    t = st.throughput(now=1010.0)                    # covers seconds 950 .. 1009
    assert len(t) == 60
    assert t[1000 - 950] == 20.0 and t[1005 - 950] == 1.0
    assert sum(t) == 21.0
    assert st.throughput(now=1100.0) == [0.0] * 60   # everything is older than 60 s now


def test_maybe_write_writes_at_most_once_a_second(tmp_path):
    st, path = ServerStats(), str(tmp_path / "stats.json")
    assert st.maybe_write(path, []) is True
    assert st.maybe_write(path, []) is False         # too soon
    assert json.load(open(path))["clients"] == []
