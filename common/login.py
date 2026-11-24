"""Login after the handshake (Section 4), on the same TCP connection.

Both messages are AES-GCM packets made with common/packet.py, using the handshake keys:
  client -> server : type LOGIN, c2s key, payload = name_len(1) + name + password
  server -> client : type LOGIN, s2c key, payload = b"\\x01" + 4-byte tunnel IP  (accept)
                                                  or b"\\x00"                    (reject)
The reject message says nothing about WHY. The nonce uses seq = 2**63, a number the UDP
data packets will never reach, so the same key never sees the same nonce twice.
"""
import socket
import threading
import time
from dataclasses import dataclass

from common.handshake import recv_msg, send_msg
from common.packet import TYPE_LOGIN, decode, encode
from common.users import check_password

LOGIN_SEQ = 1 << 63
FAIL_DELAY = 1.0          # seconds we wait before saying "reject" (slows password guessing)


class LoginError(Exception):
    pass


@dataclass
class Session:
    """Everything the server knows about one client."""
    user: str
    session_id: int
    c2s: bytes
    s2c: bytes
    ip: str                # tunnel address, like 10.8.0.2
    addr: tuple = None     # UDP address the client sends from (learned from its first packet)
    seq: int = 0           # counts packets we send to this client


class Sessions:
    """The server's table of clients, found by session_id (UDP in) or tunnel IP (tun out)."""

    def __init__(self):
        self.lock = threading.Lock()      # login threads and the main loop share this
        self.by_id = {}
        self.by_ip = {}

    def add(self, user, session_id, c2s, s2c):
        """Give the client the lowest free address from 10.8.0.2. None if none is free."""
        with self.lock:
            if session_id in self.by_id:
                return None
            for n in range(2, 255):
                ip = f"10.8.0.{n}"
                if ip not in self.by_ip:
                    s = Session(user, session_id, c2s, s2c, ip)
                    self.by_id[session_id] = self.by_ip[ip] = s
                    return s
            return None


def server_login(conn, c2s, s2c, session_id, users, sessions, delay=FAIL_DELAY):
    """Read the login, check it, answer. Returns the new Session, or None if refused."""
    session = None
    try:
        ptype, _, sid, _, plain = decode(c2s, recv_msg(conn))
        if ptype != TYPE_LOGIN or sid != session_id:
            raise ValueError("wrong packet")
        name_len = plain[0]
        name = plain[1:1 + name_len].decode()
        password = plain[1 + name_len:].decode()
        if check_password(users, name, password):
            session = sessions.add(name, session_id, c2s, s2c)
    except Exception:
        session = None                    # a broken login is treated like a wrong one
    if session:
        answer = b"\x01" + socket.inet_aton(session.ip)
    else:
        time.sleep(delay)
        answer = b"\x00"
    send_msg(conn, encode(s2c, TYPE_LOGIN, 0, session_id, LOGIN_SEQ, answer))
    return session


def client_login(conn, c2s, s2c, session_id, name, password):
    """Send the login. Returns our tunnel IP as text, or raises LoginError."""
    nb = name.encode()
    payload = bytes([len(nb)]) + nb + password.encode()
    send_msg(conn, encode(c2s, TYPE_LOGIN, 0, session_id, LOGIN_SEQ, payload))
    try:
        _, _, _, _, answer = decode(s2c, recv_msg(conn))
    except Exception:
        raise LoginError("no valid answer from server")
    if answer[:1] != b"\x01" or len(answer) != 5:
        raise LoginError("login refused")
    return socket.inet_ntoa(answer[1:])
