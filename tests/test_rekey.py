import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common.packet import TYPE_DATA, decode
from common.rekey import KeyRing, RekeyError, client_rekey, server_rekey
from common.handshake import recv_msg, send_msg

SID = 77


def pair():
    """A client ring and a server ring that start with the same epoch-0 keys."""
    return KeyRing(b"c" * 32, b"s" * 32), KeyRing(b"s" * 32, b"c" * 32)


def do_rekey(c, s):
    """Run a real rekey between the two rings over a local socket pair."""
    a, b = socket.socketpair()

    def server():
        reply, _ = server_rekey(recv_msg(b), s, SID)
        send_msg(b, reply)

    t = threading.Thread(target=server)
    t.start()
    epoch = client_rekey(a, c, SID)
    t.join()
    return epoch


def test_new_epoch_gives_new_keys_that_match():
    c, s = pair()
    old_send = c.cur.send_key
    assert do_rekey(c, s) == 1
    assert c.cur.epoch == s.cur.epoch == 1
    assert c.cur.send_key != old_send                       # new keys...
    assert c.cur.send_key == s.cur.recv_key                 # ...and both sides agree
    assert c.cur.recv_key == s.cur.send_key
    assert c.cur.send_key != c.cur.recv_key                 # one key per direction
    # a packet sealed by the client in epoch 1 opens at the server and carries epoch 1 in the header
    pkt = c.seal(TYPE_DATA, SID, b"hello")
    assert pkt[1] == 1
    assert decode(s.recv_keys(pkt[1]).recv_key, pkt)[4] == b"hello"


def test_old_epoch_accepted_during_overlap_then_rejected():
    c, s = pair()
    c.rotate(b"x" * 32, b"y" * 32, now=100.0)               # epoch 1; epoch 0 stays until 100 + 5
    assert c.recv_keys(0, now=102.0).epoch == 0             # in flight packet still decrypts
    assert c.recv_keys(1, now=102.0).epoch == 1
    assert c.recv_keys(0, now=106.0) is None                # overlap over: forgotten
    assert c.prev is None


def test_replay_window_and_counter_reset_per_epoch():
    c, s = pair()
    assert c.cur.window.accept(0) and not c.cur.window.accept(0)
    assert c.seal(TYPE_DATA, SID, b"a")[6:14] == (0).to_bytes(8, "big")   # seq 0 and 1 used in epoch 0
    c.seal(TYPE_DATA, SID, b"b")
    c.rotate(b"x" * 32, b"y" * 32)
    assert c.cur.window.accept(0)                           # seq 0 is new again in the new epoch
    assert c.seal(TYPE_DATA, SID, b"c")[6:14] == (0).to_bytes(8, "big")   # counter restarted
    assert c.prev.window.accept(1)                          # the old window is still its own


def test_wrong_epoch_dropped_and_counted():
    c, s = pair()
    c.rotate(b"x" * 32, b"y" * 32, now=100.0)
    assert c.recv_keys(7, now=101.0) is None                # never existed
    assert c.recv_keys(0, now=200.0) is None                # long gone
    assert c.bad_epoch == 2


def test_rekey_with_wrong_keys_fails():
    c, _ = pair()
    s = KeyRing(b"q" * 32, b"z" * 32)                       # a server that does not share our keys
    with pytest.raises(RekeyError):
        a, b = socket.socketpair()
        a.settimeout(1)
        threading.Thread(target=lambda: send_msg(b, b"garbage" * 10), daemon=True).start()
        client_rekey(a, c, SID)
    assert c.cur.epoch == 0                                 # nothing changed
