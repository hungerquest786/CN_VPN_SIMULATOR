"""Periodic rekeying (Section 7).

Every epoch has its own pair of keys, its own sequence counter (starting at 0) and its own
replay window, so a nonce (session_id + seq) is never used twice under the same key.
The epoch number goes in the packet header (key_epoch, 1 byte, wraps after 255).

How a rekey works (the client starts it, over the TCP connection from the login, which stays open):
  client -> server : fresh X25519 public key   (sealed with the CURRENT keys, type REKEY)
  server -> client : fresh X25519 public key   (sealed with the CURRENT keys, type REKEY)
  both : new keys = HKDF(new shared secret, salt = both public keys + session_id + new epoch)
Why this is secure: both messages are AES-GCM packets under the current keys, so only the real
peer can make them (an attacker cannot swap in their own key), and a fresh X25519 pair means an
old key leaking later does not reveal the new keys. The TCP connection also makes it reliable,
so we need no retransmit logic.
The old keys stay for OVERLAP seconds, so UDP packets already in flight still decrypt.
"""
import struct
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from common.handshake import raw, recv_msg, send_msg
from common.keys import derive_keys
from common.packet import TYPE_REKEY, decode, encode
from common.replay import ReplayWindow

REKEY_SEQ = (1 << 63) + 1   # seq for the one TCP rekey message per epoch and direction.
                            # (login used 2**63; UDP data never gets that high, so no nonce repeats)
OVERLAP = 5.0               # seconds the previous epoch's keys still work after a rekey
REKEY_EVERY = 120           # default seconds between rekeys


class RekeyError(Exception):
    pass


class EpochKeys:
    """The keys, send counter and replay window of ONE epoch."""

    def __init__(self, epoch, send_key, recv_key):
        self.epoch = epoch
        self.send_key = send_key
        self.recv_key = recv_key
        self.send_seq = 0                 # every epoch starts counting at 0
        self.window = ReplayWindow()      # every epoch has a fresh replay window

    def take_seq(self):
        seq = self.send_seq
        self.send_seq += 1
        return seq


class KeyRing:
    """The current epoch plus (briefly) the previous one."""

    def __init__(self, send_key, recv_key, overlap=OVERLAP):
        self.cur = EpochKeys(0, send_key, recv_key)
        self.prev = None
        self.prev_until = 0.0
        self.overlap = overlap
        self.bad_epoch = 0                # packets dropped because their epoch is not usable
        self.replays = 0                  # packets dropped by a replay window

    def rotate(self, send_key, recv_key, now=None):
        """Switch to the next epoch. The old one is kept for `overlap` seconds."""
        now = time.monotonic() if now is None else now
        new = EpochKeys((self.cur.epoch + 1) % 256, send_key, recv_key)
        self.prev, self.prev_until = self.cur, now + self.overlap
        self.cur = new

    def recv_keys(self, epoch, now=None):
        """Keys for a packet with this epoch, or None (and counted) if it is neither current nor overlap."""
        now = time.monotonic() if now is None else now
        if epoch == self.cur.epoch:
            return self.cur
        if self.prev is not None and epoch == self.prev.epoch and now < self.prev_until:
            return self.prev
        if self.prev is not None and now >= self.prev_until:
            self.prev = None              # overlap is over: forget the old keys
        self.bad_epoch += 1
        return None

    def seal(self, ptype, session_id, plain):
        """Encrypt a packet with the current epoch's key and its next sequence number."""
        ek = self.cur                     # read once: key, epoch and counter belong together
        return encode(ek.send_key, ptype, ek.epoch, session_id, ek.take_seq(), plain)


def _new_keys(my_priv, their_pub, c_pub, s_pub, session_id, new_epoch):
    shared = my_priv.exchange(X25519PublicKey.from_public_bytes(their_pub))
    transcript = c_pub + s_pub + struct.pack(">IB", session_id, new_epoch)
    return derive_keys(shared, transcript)          # (c2s, s2c)


def _open(ek, msg, session_id):
    """Check a TCP rekey message made with epoch `ek`. Returns the 32-byte public key inside."""
    try:
        ptype, epoch, sid, seq, key = decode(ek.recv_key, msg)
    except ValueError as e:
        raise RekeyError(str(e))
    if ptype != TYPE_REKEY or epoch != ek.epoch or sid != session_id or seq != REKEY_SEQ or len(key) != 32:
        raise RekeyError("wrong rekey message")
    return key


def client_rekey(conn, ring, session_id):
    """Client side: run one rekey on the open TCP connection. Raises RekeyError on any problem."""
    ek = ring.cur
    priv = X25519PrivateKey.generate()
    c_pub = raw(priv.public_key())
    try:
        send_msg(conn, encode(ek.send_key, TYPE_REKEY, ek.epoch, session_id, REKEY_SEQ, c_pub))
        s_pub = _open(ek, recv_msg(conn), session_id)
    except Exception as e:      # network error, bad tag, wrong message: all mean the rekey failed
        raise RekeyError(f"rekey failed: {e}")
    c2s, s2c = _new_keys(priv, s_pub, c_pub, s_pub, session_id, (ek.epoch + 1) % 256)
    ring.rotate(send_key=c2s, recv_key=s2c)
    return ring.cur.epoch


def server_rekey(msg, ring, session_id):
    """Server side: answer a client's rekey message. Returns (reply_bytes, new_epoch).
    We switch to the new keys here; the caller sends the reply right after."""
    ek = ring.cur
    c_pub = _open(ek, msg, session_id)
    priv = X25519PrivateKey.generate()
    s_pub = raw(priv.public_key())
    reply = encode(ek.send_key, TYPE_REKEY, ek.epoch, session_id, REKEY_SEQ, s_pub)  # old keys
    c2s, s2c = _new_keys(priv, c_pub, c_pub, s_pub, session_id, (ek.epoch + 1) % 256)
    ring.rotate(send_key=s2c, recv_key=c2s)
    return reply, ring.cur.epoch
