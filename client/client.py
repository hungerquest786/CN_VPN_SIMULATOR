"""VPN client (Section 2): runs inside the client1 namespace.
Packets from tun0 -> encrypt -> UDP to server.  UDP from server -> decrypt -> tun0.
"""
import os
import select
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common.keys import load_psk, derive_keys
from common.packet import encode, decode, TYPE_DATA
from common.tun import open_tun

SERVER = ("10.0.3.2", 51820)

c2s_key, s2c_key = derive_keys(load_psk())   # client encrypts with c2s, decrypts with s2c
# No handshake yet: read the session id the server wrote (start the server first).
with open("session.id") as f:
    session_id = int(f.read())

tun_fd, _ = open_tun("tun0", "10.8.0.2/24")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print(f"client up, sending to {SERVER}, session_id={session_id}")

seq = 0   # counts packets we send; never reused

while True:
    ready, _, _ = select.select([tun_fd, sock], [], [])
    if tun_fd in ready:
        plain = os.read(tun_fd, 2000)
        sock.sendto(encode(c2s_key, TYPE_DATA, 0, session_id, seq, plain), SERVER)
        seq += 1
    if sock in ready:
        data, _ = sock.recvfrom(2000)
        try:
            _, _, sid, _, plain = decode(s2c_key, data)
        except ValueError as e:
            print("dropped:", e)
        else:
            if sid == session_id:
                os.write(tun_fd, plain)
