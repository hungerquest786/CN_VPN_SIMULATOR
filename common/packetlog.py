"""Packet Inspector log (Section 12, Stage 1): the last 20 packets the Mini VPN server saw.

The server calls received() / sent() for each UDP packet. We keep only METADATA: addresses, sizes,
the header fields and the inner IP header fields. We never keep payload bytes, keys or passwords.
About once a second the list is written to packets.json, atomically (same helper as stats.json).
Only the server's main loop uses this object, so it needs no lock.
"""
import socket
import struct
import time
from collections import deque

from common.packet import HEADER_FMT, HEADER_LEN, TYPE_DATA, TYPE_KEEPALIVE, TYPE_LOGIN, TYPE_REKEY
from common.serverstats import WRITE_EVERY, write_stats

MAX_PACKETS = 20
TYPE_NAMES = {TYPE_DATA: "data", TYPE_LOGIN: "login", TYPE_KEEPALIVE: "keepalive", TYPE_REKEY: "rekey"}
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def decode_header(data):
    """The 14 header bytes as a dict, or None if the packet is shorter than a header.
    The header is not encrypted, so we can read it even when the packet is later refused.
    (For a refused packet these numbers are unchecked: anyone could have written them.)"""
    if len(data) < HEADER_LEN:
        return None
    ptype, epoch, sid, seq = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
    return {"type": TYPE_NAMES.get(ptype, f"type {ptype}"), "session_id": sid, "key_epoch": epoch, "counter": seq}


def describe_inner(plain):
    """Source, destination, protocol and size of a decrypted IPv4 packet. None if it is empty or not IPv4."""
    if len(plain) < 20 or plain[0] >> 4 != 4:
        return None
    return {"src": socket.inet_ntoa(plain[12:16]), "dst": socket.inet_ntoa(plain[16:20]),
            "protocol": PROTO_NAMES.get(plain[9], f"proto {plain[9]}"), "size": len(plain)}


class PacketLog:
    def __init__(self, local):
        self.local = local                       # (ip, port) of our UDP socket
        self.packets = deque(maxlen=MAX_PACKETS)
        self.last_write = 0.0

    def _add(self, direction, src, dst, wire, plain, reason, now):
        self.packets.append({
            "time": time.time() if now is None else now,
            "direction": direction,              # "client to server" or "server to client"
            "outer": {"src_ip": src[0], "src_port": src[1], "dst_ip": dst[0], "dst_port": dst[1], "size": len(wire)},
            "header": decode_header(wire),
            "inner": describe_inner(plain),
            "result": "dropped" if reason else "accepted",
            "reason": reason,
        })

    def received(self, addr, wire, reason=None, plain=b"", now=None):
        """A UDP packet from a client. reason=None means accepted, otherwise the reason it was dropped."""
        self._add("client to server", addr, self.local, wire, plain, reason, now)

    def sent(self, addr, wire, plain=b"", now=None):
        """A UDP packet we sent to a client."""
        self._add("server to client", self.local, addr, wire, plain, None, now)

    def snapshot(self, now=None):
        return {"server_time": time.time() if now is None else now, "packets": list(self.packets)[::-1]}   # newest first

    def maybe_write(self, path, now=None):
        """Write the file if a second has passed since the last write. Returns True if it wrote."""
        mono = time.monotonic()
        if mono - self.last_write < WRITE_EVERY:
            return False
        self.last_write = mono
        write_stats(path, self.snapshot(now))
        return True
