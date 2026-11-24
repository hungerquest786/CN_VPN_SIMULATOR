"""Replay protection: a sliding window of the last 1024 sequence numbers (Section 6).

Each session keeps one window per direction. A packet is accepted only if its seq was not
seen before and is not older than the window. Out-of-order packets inside the window are fine.
Call accept() only AFTER the packet decrypted correctly, so a forged packet cannot move the window.
"""

WINDOW = 1024


class ReplayWindow:
    def __init__(self, size=WINDOW):
        self.size = size
        self.top = -1        # highest seq seen so far
        self.bits = 0        # bit i set means "seq (top - i) was seen"
        self.dropped = 0     # how many packets we refused

    def accept(self, seq):
        """True if the packet is new (and remember it), False if it is a replay or too old."""
        if seq > self.top:                           # newest so far: slide the window forward
            shift = seq - self.top
            self.bits = 1 if shift >= self.size else ((self.bits << shift) | 1) & ((1 << self.size) - 1)
            self.top = seq
            return True
        back = self.top - seq                        # how far behind the newest packet
        if back >= self.size or (self.bits >> back) & 1:
            self.dropped += 1                        # too old, or already seen
            return False
        self.bits |= 1 << back                       # late but new: mark it as seen
        return True
