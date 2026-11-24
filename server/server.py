"""VPN server (Section 2): runs inside the serverA namespace.
Packets from tun0 -> encrypt -> UDP to client.  UDP from client -> decrypt -> tun0.
"""
import os
import select
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common.keys import load_psk, derive_keys
from common.packet import encode, decode, TYPE_DATA
from common.tun import open_tun

BIND = ("10.0.3.2", 51820)

c2s_key, s2c_key = derive_keys(load_psk())   # server decrypts with c2s, encrypts with s2c
session_id = int.from_bytes(os.urandom(4), "big")   # new random id every run
# No handshake yet, so the client reads the id from this file.
with open("session.id", "w") as f:
    f.write(str(session_id))

tun_fd, _ = open_tun("tun0", "10.8.0.1/24")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(BIND)
print(f"server up on {BIND}, session_id={session_id}")

client_addr = None   # learned from the first valid packet we receive
seq = 0              # counts packets we send; never reused

while True:
    ready, _, _ = select.select([tun_fd, sock], [], [])
    if sock in ready:
        data, addr = sock.recvfrom(2000)
        try:
            _, _, sid, _, plain = decode(c2s_key, data)
        except ValueError as e:
            print("dropped:", e)          # bad packets are just ignored
        else:
            if sid == session_id:
                client_addr = addr
                os.write(tun_fd, plain)   # hand the IP packet to the kernel
    if tun_fd in ready:
        plain = os.read(tun_fd, 2000)
        if client_addr:                   # nobody to send to until client speaks
            sock.sendto(encode(s2c_key, TYPE_DATA, 0, session_id, seq, plain), client_addr)
            seq += 1
