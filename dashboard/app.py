"""Read-only dashboard (Section 9). Run in the root namespace; serves 127.0.0.1:5000 only.

    python3 dashboard/app.py [--stats-file stats.json] [--results-file results/summary.csv] [--packets-file packets.json]

It never changes anything: /api/stats shows what the VPN server wrote, /api/results shows the CSV,
/api/packets shows the last packets the server wrote.
"""
import argparse
import json
import os
import time

from flask import Flask, jsonify, send_from_directory

try:
    from dashboard.results import ResultsError, read_results
except ImportError:                       # started as `python3 dashboard/app.py`
    from results import ResultsError, read_results

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STALE_AFTER = 5       # seconds; stats.json older than this means no VPN server is running


def read_stats(path, now=None):
    """The server's stats plus "running": True, or {"running": False} if missing, old or unreadable."""
    now = time.time() if now is None else now
    try:
        with open(path) as f:
            data = json.load(f)
        age = now - float(data["server_time"])
    except (OSError, ValueError, KeyError, TypeError):    # missing, half-written, not our format
        return {"running": False}
    if age > STALE_AFTER:
        return {"running": False}
    data["running"] = True
    return data


def create_app(stats_file, results_file, packets_file=None):
    app = Flask(__name__, static_folder=None)
    if packets_file is None:           # default: next to the stats file
        packets_file = os.path.join(os.path.dirname(os.path.abspath(stats_file)), "packets.json")

    @app.get("/")
    def index():
        return send_from_directory(os.path.join(HERE, "static"), "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(os.path.join(HERE, "static"), name)

    @app.get("/api/stats")
    def api_stats():
        return jsonify(read_stats(stats_file))

    @app.get("/api/packets")
    def api_packets():            # the server's last 20 packets; same fresh/stale rule as /api/stats
        return jsonify(read_stats(packets_file))

    @app.get("/api/results")
    def api_results():
        try:
            return jsonify(read_results(results_file))
        except ResultsError as e:
            return jsonify({"available": False, "error": str(e)})

    @app.after_request
    def no_cache(resp):
        resp.headers["Cache-Control"] = "no-store"
        return resp

    return app


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Mini VPN dashboard (read-only)")
    ap.add_argument("--stats-file", default=os.path.join(ROOT, "stats.json"))
    ap.add_argument("--results-file", default=os.path.join(ROOT, "results", "summary.csv"))
    ap.add_argument("--packets-file", default=os.path.join(ROOT, "packets.json"))
    a = ap.parse_args()
    create_app(a.stats_file, a.results_file, a.packets_file).run(host="127.0.0.1", port=5000)
