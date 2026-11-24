import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from dashboard.app import create_app, read_stats


def stats_file(tmp_path, server_time):
    p = tmp_path / "stats.json"
    p.write_text(json.dumps({"server_time": server_time, "clients": [], "counters": {}}))
    return str(p)


def test_missing_stats_file_means_no_server(tmp_path):
    assert read_stats(str(tmp_path / "stats.json")) == {"running": False}


def test_fresh_file_is_running_and_old_file_is_not(tmp_path):
    p = stats_file(tmp_path, server_time=1000.0)
    assert read_stats(p, now=1003.0)["running"] is True
    assert read_stats(p, now=1006.0) == {"running": False}      # older than 5 s


def test_unreadable_file_means_no_server(tmp_path):
    p = tmp_path / "stats.json"
    p.write_text("{half a fi")
    assert read_stats(str(p)) == {"running": False}


def test_api_routes(tmp_path):
    client = create_app(str(tmp_path / "none.json"), str(tmp_path / "none.csv")).test_client()
    assert client.get("/api/stats").get_json() == {"running": False}
    assert client.get("/api/results").get_json() == {"available": False}     # "No results yet"
    assert client.get("/").status_code == 200
    assert client.get("/static/app.js").status_code == 200
