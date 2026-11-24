"""Counts packets the server drops, so one bad stream cannot flood the screen (Section 6)."""
import time

SHOW_FIRST = 5        # print the details of this many drops (to see what they are), then only count
SUMMARY_EVERY = 10    # at most one summary line per this many seconds


class DropStats:
    def __init__(self):
        self.counts = {}          # reason -> total dropped
        self.unreported = 0       # dropped since the last summary
        self.shown = 0
        self.last_summary = time.monotonic()

    def add(self, reason, detail=""):
        """Count one drop. Returns a line to print for the first few drops, else None."""
        self.counts[reason] = self.counts.get(reason, 0) + 1
        self.unreported += 1
        if self.shown < SHOW_FIRST:
            self.shown += 1
            return f"dropped ({reason}): {detail}"
        return None

    def summary(self, now=None):
        """A summary line if something was dropped and 10 s passed since the last one, else None."""
        now = time.monotonic() if now is None else now
        if not self.unreported or now - self.last_summary < SUMMARY_EVERY:
            return None
        line = f"dropped {self.unreported} packets in the last {SUMMARY_EVERY}s+ " \
               f"(totals: {', '.join(f'{k}={v}' for k, v in self.counts.items())})"
        self.unreported = 0
        self.last_summary = now
        return line
