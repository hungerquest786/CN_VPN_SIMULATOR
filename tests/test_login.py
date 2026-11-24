import os
import socket
import sys
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common.handshake import (client_finish, client_hello, make_cert, raw,
                              recv_msg, send_msg, server_reply)
from common.login import LoginError, Sessions, client_login, server_login
from common.users import add_user, check_password, load_users

CA = Ed25519PrivateKey.generate()
KEY = Ed25519PrivateKey.generate()
CERT = make_cert(CA, "vpn-server", raw(KEY.public_key()), int(time.time()) + 3600)


@pytest.fixture
def users(tmp_path):
    path = str(tmp_path / "users.json")
    add_user(path, "alice", "alice-pw")
    add_user(path, "bob", "bob-pw")
    return load_users(path)


def login(users, sessions, name, password):
    """Do a whole handshake + login over a local socket pair. Returns (client result, session)."""
    a, b = socket.socketpair()
    out = {}

    def server():
        hello = recv_msg(b)
        reply, c2s, s2c, sid = server_reply(hello, CERT, KEY)
        send_msg(b, reply)
        out["session"] = server_login(b, c2s, s2c, sid, users, sessions, delay=0.01)

    t = threading.Thread(target=server)
    t.start()
    priv, hello = client_hello()
    send_msg(a, hello)
    keys = client_finish(priv, hello, recv_msg(a), CA.public_key(), "vpn-server")
    try:
        result = client_login(a, *keys, name, password)
    except LoginError:
        result = None
    t.join()
    return result, out["session"]


def test_correct_password_accepted(users):
    ip, session = login(users, Sessions(), "alice", "alice-pw")
    assert ip == "10.8.0.2" and session.user == "alice"


def test_wrong_password_rejected(users):
    sessions = Sessions()
    ip, session = login(users, sessions, "alice", "nope")
    assert ip is None and session is None and not sessions.by_id


def test_unknown_user_rejected(users):
    ip, session = login(users, Sessions(), "mallory", "alice-pw")
    assert ip is None and session is None


def test_two_clients_get_different_addresses(users):
    sessions = Sessions()
    ip1, s1 = login(users, sessions, "alice", "alice-pw")
    ip2, s2 = login(users, sessions, "bob", "bob-pw")
    assert (ip1, ip2) == ("10.8.0.2", "10.8.0.3")
    assert s1.session_id != s2.session_id and s1.c2s != s2.c2s   # own session, own keys
    assert sessions.by_ip["10.8.0.3"] is s2


def test_stored_hash_uses_random_salt(tmp_path):
    path = str(tmp_path / "u.json")
    add_user(path, "a", "same")
    add_user(path, "b", "same")
    u = load_users(path)
    assert u["a"]["salt"] != u["b"]["salt"] and u["a"]["hash"] != u["b"]["hash"]
    assert "same" not in open(path).read()
    assert check_password(u, "a", "same") and not check_password(u, "a", "other")
