"""VPN server (Section 6): runs inside the serverA namespace.
Each client: handshake + login over TCP 51821, then data over UDP 51820.
Many clients at once. Each has its own session (session_id, keys, tunnel IP, UDP address).
Packets from tun0 -> find the client by destination IP -> encrypt -> UDP.
UDP from a client -> find the session by session_id -> decrypt -> tun0.
Section 5: at start we turn on IP forwarding and NAT, so traffic from the tunnel network
leaves serverA with serverA's own address (10.0.3.2). At exit we remove the NAT rule.
Section 6: answers keepalives, removes clients silent for 60 s (frees their address),
drops replayed packets (sliding window) and packets with a wrong inner source IP.
"""
import atexit
import os
import signal
import subprocess
import select
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common.handshake import HandshakeError, recv_msg, send_msg, server_reply
from common.dropstats import DropStats
from common.login import DEAD_AFTER, Sessions, server_login
from common.packet import encode, decode, TYPE_DATA, TYPE_KEEPALIVE
from common.tun import open_tun
from common.users import load_users

BIND = ("10.0.3.2", 51820)        # UDP data
TCP_BIND = ("10.0.3.2", 51821)    # TCP handshake + login
USERS_FILE = "users.json"

with open("certs/server.cert", "rb") as f:
    cert = f.read()
with open("certs/server.key", "rb") as f:
    signing_key = Ed25519PrivateKey.from_private_bytes(f.read())

sessions = Sessions()
stats = DropStats()   # counts tunnel packets we refuse (not IPv4, wrong source)

NAT_TABLE = "minivpn_nat"   # our own nft table, so removing it cannot touch anything else


def start_nat():
    """Forward packets between tun0 and the real network, and hide 10.8.0.0/24 behind our address."""
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:    # this namespace only (serverA)
        f.write("1")
    rules = f"""
    table ip {NAT_TABLE} {{
        chain postrouting {{
            type nat hook postrouting priority 100;
            ip saddr 10.8.0.0/24 oifname != "tun0" masquerade
        }}
    }}"""
    subprocess.run(["nft", "-f", "-"], input=rules.encode(), check=True)
    atexit.register(stop_nat)


def stop_nat():
    subprocess.run(["nft", "delete", "table", "ip", NAT_TABLE], check=False)
    print("NAT rule removed")


# Ctrl-C raises KeyboardInterrupt; a plain `kill` (SIGTERM) is turned into a normal exit,
# so in both cases atexit runs and the rule is removed.
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))


def handle_client(conn, peer):
    """Runs in its own thread, so a slow or wrong-password client does not block the others."""
    try:
        with conn:
            conn.settimeout(10)                   # do not wait forever for a slow client
            hello = recv_msg(conn)
            reply, c2s, s2c, sid = server_reply(hello, cert, signing_key)
            send_msg(conn, reply)
            # Read users.json at every login, so new users work without a restart.
            s = server_login(conn, c2s, s2c, sid, load_users(USERS_FILE), sessions)
            if s:
                print(f"{peer[0]}: user {s.user!r} logged in, got {s.ip}, session_id={sid}")
            else:
                print(f"{peer[0]}: login refused")
    except (HandshakeError, OSError) as e:
        print(f"{peer[0]}: handshake failed: {e}")


subprocess.run(["nft", "delete", "table", "ip", NAT_TABLE], capture_output=True)  # leftover from a crash
tun_fd, _ = open_tun("tun0", "10.8.0.1/24")
start_nat()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(BIND)
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(TCP_BIND)
listener.listen(16)
print(f"server up: UDP {BIND}, TCP {TCP_BIND}")

# Only this main loop touches the sockets and each session's seq counter.
try:
    while True:
        ready, _, _ = select.select([tun_fd, sock, listener], [], [], 1.0)   # wake up every second
        for dead in sessions.expire():
            print(f"session {dead.session_id} ({dead.user}) silent for {DEAD_AFTER}s: removed, {dead.ip} is free")
        line = stats.summary()            # at most one line every 10 s
        if line:
            print(line)
        if listener in ready:
            conn, peer = listener.accept()
            threading.Thread(target=handle_client, args=(conn, peer), daemon=True).start()
        if sock in ready:
            data, addr = sock.recvfrom(2000)
            try:
                # session_id sits in header bytes 2..5; it tells us whose key to use.
                s = sessions.by_id.get(struct.unpack(">I", data[2:6])[0]) if len(data) >= 14 else None
                if s is None:
                    raise ValueError("unknown session")
                ptype, _, sid, seq, plain = decode(s.c2s, data)
            except ValueError as e:
                print("dropped:", e)          # bad packets are just ignored
                continue
            if not s.window.accept(seq):      # only checked after decrypt worked
                print(f"replay dropped: session {sid} seq {seq} (total dropped {s.window.dropped})")
                continue
            s.addr = addr                     # the packet was real, so remember where it came from
            s.last_heard = time.monotonic()
            if ptype == TYPE_KEEPALIVE:       # answer with our own keepalive
                sock.sendto(encode(s.s2c, TYPE_KEEPALIVE, 0, sid, s.seq, b""), addr)
                s.seq += 1
            elif ptype == TYPE_DATA:
                # Source check: bytes 12..15 of an IPv4 packet are the source address.
                # It must be the address we gave this client. Anything that is not IPv4
                # (first 4 bits of the packet = version) is dropped too.
                reason = detail = None
                if len(plain) < 20 or plain[0] >> 4 != 4:
                    reason = "not IPv4"
                    detail = f"session {sid}, IP version {plain[0] >> 4 if plain else '?'}, {len(plain)} bytes"
                    if plain[:1] == b"\x60" and len(plain) >= 24:
                        detail += ", IPv6 source " + socket.inet_ntop(socket.AF_INET6, plain[8:24])
                elif socket.inet_ntoa(plain[12:16]) != s.ip:
                    reason = "wrong source"
                    detail = f"session {sid}, IP version 4, source {socket.inet_ntoa(plain[12:16])}, should be {s.ip}"
                if reason:
                    line = stats.add(reason, detail)
                    if line:
                        print(line)
                else:
                    os.write(tun_fd, plain)   # hand the IP packet to the kernel
        if tun_fd in ready:
            plain = os.read(tun_fd, 2000)
            # Bytes 16..19 of an IPv4 packet are the destination address.
            s = sessions.by_ip.get(socket.inet_ntoa(plain[16:20])) if len(plain) >= 20 else None
            if s and s.addr:                  # drop it if we know no such client (or it never spoke)
                sock.sendto(encode(s.s2c, TYPE_DATA, 0, s.session_id, s.seq, plain), s.addr)
                s.seq += 1
except KeyboardInterrupt:
    print("\nserver stopped")                # exiting normally runs the NAT cleanup
