"""VPN client (Section 3): runs inside the client1 namespace.
First the handshake (TCP 51821), then data over UDP 51820.
Packets from tun0 -> encrypt -> UDP to server.  UDP from server -> decrypt -> tun0.
"""
import os
import select
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from common.handshake import HandshakeError, client_finish, client_hello, recv_msg, send_msg
from common.packet import encode, decode, TYPE_DATA
from common.tun import open_tun

SERVER = ("10.0.3.2", 51820)         # UDP data
SERVER_TCP = ("10.0.3.2", 51821)     # TCP handshake
SERVER_NAME = "vpn-server"           # the name the certificate must contain
CA_FILE = sys.argv[1] if len(sys.argv) > 1 else "certs/ca.pub"   # the CA we trust

with open(CA_FILE, "rb") as f:
    ca_public = Ed25519PublicKey.from_public_bytes(f.read())

# Handshake. If anything is wrong we stop here and never open the tunnel.
try:
    with socket.create_connection(SERVER_TCP, timeout=5) as conn:
        priv, hello = client_hello()
        send_msg(conn, hello)
        reply = recv_msg(conn)
    c2s_key, s2c_key, session_id = client_finish(priv, hello, reply, ca_public, SERVER_NAME)
except (HandshakeError, OSError) as e:
    sys.exit(f"HANDSHAKE FAILED, refusing to continue: {e}")
print("handshake OK: server certificate and signature are valid")

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
