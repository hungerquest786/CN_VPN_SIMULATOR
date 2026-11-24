import os
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common.handshake import (HandshakeError, client_finish, client_hello,
                              make_cert, raw, server_reply)

NAME = "vpn-server"


def make_server(ca, expiry=None):
    """Make a server key and a certificate signed by `ca`."""
    key = Ed25519PrivateKey.generate()
    cert = make_cert(ca, NAME, raw(key.public_key()), expiry or int(time.time()) + 3600)
    return key, cert


def run(ca, server_ca):
    """Run a whole handshake. The server's cert is signed by server_ca, the client trusts ca."""
    key, cert = make_server(server_ca)
    priv, hello = client_hello()
    reply, s_c2s, s_s2c, s_sid = server_reply(hello, cert, key)
    return priv, hello, reply, (s_c2s, s_s2c, s_sid), ca.public_key()


def test_both_sides_get_same_keys():
    ca = Ed25519PrivateKey.generate()
    priv, hello, reply, server_result, ca_pub = run(ca, ca)
    client_result = client_finish(priv, hello, reply, ca_pub, NAME)
    assert client_result == server_result
    assert client_result[0] != client_result[1]      # the two directions differ


def test_cert_from_other_ca_rejected():
    real_ca, fake_ca = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    priv, hello, reply, _, ca_pub = run(real_ca, fake_ca)   # server cert signed by fake CA
    with pytest.raises(HandshakeError):
        client_finish(priv, hello, reply, ca_pub, NAME)


@pytest.mark.parametrize("where", [-1, -70, -100, 10])
def test_tampered_server_hello_rejected(where):
    # -1 = signature, -70 = session_id, -100 = server X25519 key, 10 = inside the cert
    ca = Ed25519PrivateKey.generate()
    priv, hello, reply, _, ca_pub = run(ca, ca)
    bad = bytearray(reply)
    bad[where] ^= 1
    with pytest.raises(HandshakeError):
        client_finish(priv, hello, bytes(bad), ca_pub, NAME)


def test_tampered_client_hello_rejected():
    # An attacker changes the ClientHello on the way to the server: the server signs
    # a transcript the client does not recognise.
    ca = Ed25519PrivateKey.generate()
    key, cert = make_server(ca)
    priv, hello = client_hello()
    evil = bytearray(hello)
    evil[0] ^= 1
    reply, *_ = server_reply(bytes(evil), cert, key)
    with pytest.raises(HandshakeError):
        client_finish(priv, hello, reply, ca.public_key(), NAME)


def test_expired_cert_and_wrong_name_rejected():
    ca = Ed25519PrivateKey.generate()
    key, cert = make_server(ca, expiry=int(time.time()) - 10)
    priv, hello = client_hello()
    reply, *_ = server_reply(hello, cert, key)
    with pytest.raises(HandshakeError):
        client_finish(priv, hello, reply, ca.public_key(), NAME)
    key, cert = make_server(ca)
    reply, *_ = server_reply(hello, cert, key)
    with pytest.raises(HandshakeError):
        client_finish(priv, hello, reply, ca.public_key(), "other-name")
