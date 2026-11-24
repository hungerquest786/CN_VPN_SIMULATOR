"""VPN server (Section 5): runs inside the serverA namespace.
Each client: handshake + login over TCP 51821, then data over UDP 51820.
Many clients at once. Each has its own session (session_id, keys, tunnel IP, UDP address).
Packets from tun0 -> find the client by destination IP -> encrypt -> UDP.
UDP from a client -> find the session by session_id -> decrypt -> tun0.
Section 5: at start we turn on IP forwarding and NAT, so traffic from the tunnel network
leaves serverA with serverA's own address (10.0.3.2). At exit we remove the NAT rule.
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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common.handshake import HandshakeError, recv_msg, send_msg, server_reply
from common.login import Sessions, server_login
from common.packet import encode, decode, TYPE_DATA
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
while True:
    ready, _, _ = select.select([tun_fd, sock, listener], [], [])
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
            _, _, sid, _, plain = decode(s.c2s, data)
        except ValueError as e:
            print("dropped:", e)          # bad packets are just ignored
        else:
            s.addr = addr                 # the packet was real, so remember where it came from
            os.write(tun_fd, plain)       # hand the IP packet to the kernel
    if tun_fd in ready:
        plain = os.read(tun_fd, 2000)
        # Bytes 16..19 of an IPv4 packet are the destination address.
        s = sessions.by_ip.get(socket.inet_ntoa(plain[16:20])) if len(plain) >= 20 else None
        if s and s.addr:                  # drop it if we know no such client (or it never spoke)
            sock.sendto(encode(s.s2c, TYPE_DATA, 0, s.session_id, s.seq, plain), s.addr)
            s.seq += 1
