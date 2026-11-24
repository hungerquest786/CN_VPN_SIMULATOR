"""VPN client (Section 7): runs inside a client namespace.
Usage: client.py USERNAME [-p PASSWORD] [--ca FILE] [--split | --full]
(asks for the password if -p is missing)
  no flag : only the tunnel network 10.8.0.0/24 goes through tun0
  --split : also 10.0.3.0/24 (the servers' network) goes through tun0
  --full  : everything goes through tun0
Section 6: sends a keepalive after 25 s of silence; exits if the server is silent for 60 s;
drops replayed packets from the server.
Section 7: every --rekey-interval seconds (default 120) it rekeys over the TCP connection,
which stays open after login. The old keys still work for a few seconds.
First handshake + login (TCP 51821), then data over UDP 51820.
Packets from tun0 -> encrypt -> UDP to server.  UDP from server -> decrypt -> tun0.
"""
import argparse
import atexit
import getpass
import os
import select
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from common.handshake import HandshakeError, client_finish, client_hello, recv_msg, send_msg
from common.login import DEAD_AFTER, KEEPALIVE_AFTER, LoginError, client_login
from common.rekey import REKEY_EVERY, KeyRing, RekeyError, client_rekey
from common.packet import decode, TYPE_DATA, TYPE_KEEPALIVE
from common.tun import open_tun

SERVER = ("10.0.3.2", 51820)         # UDP data
SERVER_TCP = ("10.0.3.2", 51821)     # TCP handshake
SERVER_NAME = "vpn-server"           # the name the certificate must contain

ap = argparse.ArgumentParser()
ap.add_argument("username")
ap.add_argument("-p", "--password")
ap.add_argument("--ca", default="certs/ca.pub")      # the CA we trust
mode = ap.add_mutually_exclusive_group()
mode.add_argument("--split", action="store_true")
mode.add_argument("--full", action="store_true")
ap.add_argument("--rekey-interval", type=float, default=REKEY_EVERY, help="seconds between rekeys")
ap.add_argument("--replay-test", action="store_true", help=argparse.SUPPRESS)  # hidden demo flag
args = ap.parse_args()
password = args.password if args.password is not None else getpass.getpass("Password: ")

with open(args.ca, "rb") as f:
    ca_public = Ed25519PublicKey.from_public_bytes(f.read())

# Handshake, then login. If anything is wrong we stop here and never open the tunnel.
try:
    conn = socket.create_connection(SERVER_TCP, timeout=10)   # stays open: rekeys use it later
    priv, hello = client_hello()
    send_msg(conn, hello)
    reply = recv_msg(conn)
    c2s_key, s2c_key, session_id = client_finish(priv, hello, reply, ca_public, SERVER_NAME)
    print("handshake OK: server certificate and signature are valid")
    my_ip = client_login(conn, c2s_key, s2c_key, session_id, args.username, password)
except (HandshakeError, LoginError, OSError) as e:
    sys.exit(f"FAILED, refusing to continue: {e}")
print(f"login OK, server gave us {my_ip}")

tun_fd, _ = open_tun("tun0", f"{my_ip}/24", disable_ipv6=True)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Routes. Every route we add is remembered so we can remove it when we exit.
added_routes = []


def add_route(*route):
    subprocess.run(["ip", "route", "add", *route], check=True)
    added_routes.append(route)


if args.split or args.full:
    # Exception route first: packets to the VPN server itself must keep going out the normal
    # way (same gateway and card the system uses today). Otherwise the encrypted packets would
    # be sent into the tunnel again and the tunnel would break.
    # `ip route get` prints e.g. "10.0.3.2 via 10.0.1.1 dev eth0 src 10.0.1.2".
    # Now tun0 exists but has no route to the server yet, so this still shows the normal path.
    found = subprocess.run(["ip", "-4", "route", "get", SERVER[0]],
                           capture_output=True, text=True, check=True).stdout.split()
    exception = [SERVER[0] + "/32"]
    if "via" in found:
        exception += ["via", found[found.index("via") + 1]]
    exception += ["dev", found[found.index("dev") + 1]]
    add_route(*exception)
if args.split:
    add_route("10.0.3.0/24", "dev", "tun0")
if args.full:
    # Two half-size routes beat the default route (0.0.0.0/0) without deleting it,
    # so removing them later puts everything back as before.
    add_route("0.0.0.0/1", "dev", "tun0")
    add_route("128.0.0.0/1", "dev", "tun0")
print("routes added:", [" ".join(r) for r in added_routes] or "none (only 10.8.0.0/24 uses tun0)")

print(f"client up, sending to {SERVER}, session_id={session_id}")

ring = KeyRing(send_key=c2s_key, recv_key=s2c_key)   # epoch 0 = handshake keys; each epoch has its own counter


def remove_routes():
    for route in reversed(added_routes):
        subprocess.run(["ip", "route", "del", *route], check=False)
    if added_routes:
        print("routes removed")


# Ctrl-C raises KeyboardInterrupt; SIGTERM is turned into a normal exit. Both reach the cleanup.
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
atexit.register(remove_routes)

last_sent = last_heard = last_rekey = time.monotonic()
replay_pending = args.replay_test    # --replay-test: send the first data packet twice

try:
    while True:
        ready, _, _ = select.select([tun_fd, sock], [], [], 1.0)
        now = time.monotonic()
        if tun_fd in ready:
            plain = os.read(tun_fd, 2000)
            packet = ring.seal(TYPE_DATA, session_id, plain)
            sock.sendto(packet, SERVER)
            if replay_pending:            # the exact same bytes again: the server must drop this copy
                sock.sendto(packet, SERVER)
                replay_pending = False
                print("replay test: sent one packet twice")
            last_sent = now
        if sock in ready:
            data, _ = sock.recvfrom(2000)
            try:
                ek = ring.recv_keys(data[1]) if len(data) > 1 else None   # header byte 1 = key_epoch
                if ek is None:
                    raise ValueError(f"epoch {data[1:2].hex()} is not current or overlap (total {ring.bad_epoch})")
                ptype, _, sid, rseq, plain = decode(ek.recv_key, data)
            except ValueError as e:
                print("dropped:", e)
            else:
                if sid == session_id:
                    if not ek.window.accept(rseq):
                        ring.replays += 1
                        print(f"replay dropped: epoch {ek.epoch} seq {rseq} (total dropped {ring.replays})")
                    else:
                        last_heard = now
                        if ptype == TYPE_DATA:
                            os.write(tun_fd, plain)   # keepalive answers just prove the server is alive
        if now - last_sent > KEEPALIVE_AFTER:         # quiet for a while: tell the server we are alive
            sock.sendto(ring.seal(TYPE_KEEPALIVE, session_id, b""), SERVER)
            last_sent = now
        if now - last_rekey >= args.rekey_interval:
            # We wait here for the server's answer (a few milliseconds). UDP packets that arrive
            # meanwhile just wait in the socket, and are read after we switched keys.
            try:
                print(f"rekeyed, now epoch {client_rekey(conn, ring, session_id)}")
            except RekeyError as e:
                print(e)
                sys.exit(1)               # keys out of step: leaving is safer than limping on
            last_rekey = time.monotonic()
        if now - last_heard > DEAD_AFTER:
            print(f"no answer from the server for {DEAD_AFTER}s, exiting")
            sys.exit(0)                               # exiting normally runs remove_routes
except KeyboardInterrupt:
    print("\nclient stopped")
