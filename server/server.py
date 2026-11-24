"""VPN server (Section 3): runs inside the serverA namespace.
A client first does the handshake over TCP 51821, then data flows over UDP 51820.
Packets from tun0 -> encrypt -> UDP to client.  UDP from client -> decrypt -> tun0.
"""
import os
import select
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from common.handshake import HandshakeError, recv_msg, send_msg, server_reply
from common.packet import encode, decode, TYPE_DATA
from common.tun import open_tun

BIND = ("10.0.3.2", 51820)        # UDP data
TCP_BIND = ("10.0.3.2", 51821)    # TCP handshake

with open("certs/server.cert", "rb") as f:
    cert = f.read()
with open("certs/server.key", "rb") as f:
    signing_key = Ed25519PrivateKey.from_private_bytes(f.read())


def do_handshake(conn):
    """Read ClientHello, send ServerHello. Returns (c2s_key, s2c_key, session_id)."""
    conn.settimeout(5)                    # do not wait forever for a slow client
    hello = recv_msg(conn)
    reply, c2s, s2c, sid = server_reply(hello, cert, signing_key)
    send_msg(conn, reply)
    return c2s, s2c, sid


c2s_key = s2c_key = session_id = None     # no session until a client does a handshake
tun_fd, _ = open_tun("tun0", "10.8.0.1/24")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(BIND)
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(TCP_BIND)
listener.listen(1)
print(f"server up: UDP {BIND}, TCP {TCP_BIND}")

client_addr = None   # learned from the first valid packet we receive
seq = 0              # counts packets we send; never reused

while True:
    ready, _, _ = select.select([tun_fd, sock, listener], [], [])
    if listener in ready:
        # A new client: one TCP connection = one session. A new handshake replaces
        # the old session (we only support one client for now).
        conn, peer = listener.accept()
        try:
            c2s_key, s2c_key, session_id = do_handshake(conn)
            client_addr, seq = None, 0
            print(f"handshake OK with {peer[0]}, session_id={session_id}")
        except (HandshakeError, OSError) as e:
            print(f"handshake failed with {peer[0]}: {e}")
        finally:
            conn.close()
    if sock in ready:
        data, addr = sock.recvfrom(2000)
        try:
            if session_id is None:
                raise ValueError("no session yet")
            _, _, sid, _, plain = decode(c2s_key, data)
        except ValueError as e:
            print("dropped:", e)          # bad packets are just ignored
        else:
            if sid == session_id:
                client_addr = addr
                os.write(tun_fd, plain)   # hand the IP packet to the kernel
    if tun_fd in ready:
        plain = os.read(tun_fd, 2000)
        if client_addr and session_id is not None:   # nobody to send to until client speaks
            sock.sendto(encode(s2c_key, TYPE_DATA, 0, session_id, seq, plain), client_addr)
            seq += 1
