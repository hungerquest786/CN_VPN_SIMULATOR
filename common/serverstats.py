"""Live numbers for the dashboard (Section 9).

The server records what happens (bytes, logins, rekeys, drops). About once a second it writes
everything to stats.json. The write is atomic: we write a temp file next to it and rename it, so
the dashboard never reads half a file. The dashboard only ever reads this file.
"""
import json
import os
import tempfile
import threading
import time
from collections import deque

MAX_EVENTS = 20          # the dashboard shows the last ~20 security events
THROUGHPUT_SECONDS = 60  # one number per second for the last minute
WRITE_EVERY = 1.0        # seconds between writes


def write_stats(path, data):
    """Write `data` as JSON to `path` atomically (temp file, then rename)."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".stats-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o644)       # mkstemp makes it private (0600); the dashboard may run as another user
        os.replace(tmp, path)      # the rename is the atomic step
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class ServerStats:
    """Counters, the event list and the per-second byte counts. Safe to use from several threads."""

    def __init__(self):
        self.lock = threading.Lock()
        self.counters = {"handshakes": 0, "refused_logins": 0, "rekeys": 0,
                         "replay_drops": 0, "wrong_source_drops": 0}
        self.events = deque(maxlen=MAX_EVENTS)
        self.bytes_per_second = {}         # whole second (int) -> bytes moved in that second
        self.last_event = None             # (type, client, time) of the newest event, to merge floods
        self.last_write = 0.0

    # --- recording -----------------------------------------------------------------------------
    def add_event(self, kind, client="", detail="", now=None):
        now = time.time() if now is None else now
        with self.lock:
            # A flood of the same drop from the same client would push everything else out of the
            # list. So the same event within one second is counted (by the caller) but not listed again.
            if kind in ("replay dropped", "wrong source dropped") and self.last_event \
                    and self.last_event[:2] == (kind, client) and now - self.last_event[2] < 1.0:
                return
            self.events.append({"time": now, "type": kind, "client": client, "detail": detail})
            self.last_event = (kind, client, now)

    def count(self, name):
        with self.lock:
            self.counters[name] += 1

    def add_bytes(self, n, now=None):
        """Bytes that crossed the UDP socket (either direction), for the throughput graph."""
        sec = int(time.time() if now is None else now)
        with self.lock:
            self.bytes_per_second[sec] = self.bytes_per_second.get(sec, 0) + n

    def handshake_done(self):
        self.count("handshakes")

    def login_ok(self, user, ip):
        self.add_event("login ok", user, ip)

    def login_refused(self, peer_ip):
        self.count("refused_logins")
        self.add_event("login refused", "", f"from {peer_ip}")

    def rekeyed(self, user, epoch):
        self.count("rekeys")
        self.add_event("rekeyed", user, f"epoch {epoch}")

    def replay_dropped(self, user, seq):
        self.count("replay_drops")
        self.add_event("replay dropped", user, f"seq {seq}")

    def wrong_source_dropped(self, user, source):
        self.count("wrong_source_drops")
        self.add_event("wrong source dropped", user, f"src {source}")

    # --- output --------------------------------------------------------------------------------
    def throughput(self, now=None):
        """Mbit/s for each of the last 60 seconds, oldest first. The current second is not finished
        yet, so the newest number is the last full second."""
        now = int(time.time() if now is None else now)
        with self.lock:
            for sec in [s for s in self.bytes_per_second if s < now - THROUGHPUT_SECONDS - 1]:
                del self.bytes_per_second[sec]            # forget old seconds
            return [round(self.bytes_per_second.get(s, 0) * 8 / 1e6, 3)
                    for s in range(now - THROUGHPUT_SECONDS, now)]

    def snapshot(self, sessions, now=None):
        """The dict that becomes stats.json. `sessions` is a list of login.Session objects."""
        now = time.time() if now is None else now
        clients = []
        for s in sorted(sessions, key=lambda x: x.connected_at):
            clients.append({
                "name": s.user,
                "tunnel_ip": s.ip,
                "real_address": s.addr[0] if s.addr else None,   # known after the first UDP packet
                "bytes_in": s.bytes_in,                           # from the client to us
                "bytes_out": s.bytes_out,                         # from us to the client
                "key_epoch": s.keys.cur.epoch,
                "connected_seconds": max(0, int(now - s.connected_at)),
            })
        with self.lock:
            counters = dict(self.counters)
            events = list(self.events)[::-1]                      # newest first
        return {"server_time": now, "clients": clients, "counters": counters,
                "throughput_mbps": self.throughput(now), "events": events}

    def maybe_write(self, path, sessions_list, now=None):
        """Write stats.json if a second has passed since the last write. Returns True if it wrote."""
        mono = time.monotonic()
        if mono - self.last_write < WRITE_EVERY:
            return False
        self.last_write = mono
        write_stats(path, self.snapshot(sessions_list, now))
        return True
