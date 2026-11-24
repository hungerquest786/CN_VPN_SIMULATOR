"""The handshake (Section 3). Two messages over TCP, each with a 2-byte length in front.

  client -> server : ClientHello = client X25519 public key (32 bytes)
  server -> client : ServerHello = cert + server X25519 public key (32)
                                   + session_id (4) + signature (64)

The signature is made with the server's Ed25519 key over everything before it
(ClientHello + cert + server public key + session_id). That is the "transcript".
Because the client's key is inside it, the signature is fresh and cannot be replayed.

Certificate = name_len(1) + name + server Ed25519 public key (32) + expiry (8, unix
seconds) + CA signature (64). The CA signs everything before its signature.
"""
import os
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from common.keys import derive_keys


class HandshakeError(Exception):
    pass


def raw(public_key):
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ---------- length-prefixed messages on a TCP socket ----------
def send_msg(sock, data):
    sock.sendall(struct.pack(">H", len(data)) + data)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise HandshakeError("connection closed")
        buf += chunk
    return buf


def recv_msg(sock):
    (n,) = struct.unpack(">H", _recv_exact(sock, 2))
    return _recv_exact(sock, n)


# ---------- certificates ----------
def make_cert(ca_private, name, server_public_raw, expiry):
    body = bytes([len(name)]) + name.encode() + server_public_raw + struct.pack(">Q", expiry)
    return body + ca_private.sign(body)


def check_cert(cert, ca_public, expected_name):
    """Return the server's Ed25519 public key (a key object) or raise HandshakeError."""
    try:
        body, ca_sig = cert[:-64], cert[-64:]
        ca_public.verify(ca_sig, body)             # was it signed by our CA?
        name_len = body[0]
        name = body[1:1 + name_len].decode()
        server_pub = body[1 + name_len:33 + name_len]
        (expiry,) = struct.unpack(">Q", body[33 + name_len:41 + name_len])
        if len(body) != 41 + name_len:
            raise ValueError("bad length")
    except InvalidSignature:
        raise HandshakeError("certificate is not signed by our CA")
    except Exception:
        raise HandshakeError("certificate is malformed")
    if name != expected_name:
        raise HandshakeError(f"certificate is for {name!r}, not {expected_name!r}")
    if expiry < time.time():
        raise HandshakeError("certificate has expired")
    return Ed25519PublicKey.from_public_bytes(server_pub)


# ---------- the three steps ----------
def client_hello():
    """Client step 1: make a fresh X25519 key pair. Returns (private_key, hello_bytes)."""
    priv = X25519PrivateKey.generate()
    return priv, raw(priv.public_key())


def server_reply(hello, cert, server_signing_key):
    """Server step: answer a ClientHello. Returns (reply_bytes, c2s_key, s2c_key, session_id)."""
    if len(hello) != 32:
        raise HandshakeError("bad ClientHello")
    priv = X25519PrivateKey.generate()               # fresh key for this session
    session_id = int.from_bytes(os.urandom(4), "big")
    part = struct.pack(">H", len(cert)) + cert + raw(priv.public_key()) + struct.pack(">I", session_id)
    transcript = hello + part
    reply = part + server_signing_key.sign(transcript)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(hello))
    c2s, s2c = derive_keys(shared, transcript)
    return reply, c2s, s2c, session_id


def client_finish(priv, hello, reply, ca_public, expected_name):
    """Client step 2: check the ServerHello. Returns (c2s_key, s2c_key, session_id).
    Raises HandshakeError if anything is wrong."""
    try:
        (cert_len,) = struct.unpack(">H", reply[:2])
        cert = reply[2:2 + cert_len]
        rest = reply[2 + cert_len:]
        if len(rest) != 32 + 4 + 64:
            raise ValueError
        server_x_pub, sid_bytes, sig = rest[:32], rest[32:36], rest[36:]
    except Exception:
        raise HandshakeError("ServerHello is malformed")
    server_sign_pub = check_cert(cert, ca_public, expected_name)   # 1. cert OK?
    transcript = hello + reply[:-64]
    try:
        server_sign_pub.verify(sig, transcript)                    # 2. signature OK?
    except InvalidSignature:
        raise HandshakeError("bad signature: handshake was changed or server is fake")
    shared = priv.exchange(X25519PublicKey.from_public_bytes(server_x_pub))
    c2s, s2c = derive_keys(shared, transcript)
    return c2s, s2c, struct.unpack(">I", sid_bytes)[0]
