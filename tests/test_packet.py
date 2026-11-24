import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common.packet import encode, decode, HEADER_LEN, TAG_LEN

KEY = bytes(range(32))


def test_round_trip():
    data = encode(KEY, 1, 0, 0xAABBCCDD, 7, b"hello vpn")
    assert len(data) == HEADER_LEN + len(b"hello vpn") + TAG_LEN   # 14 + n + 16
    assert decode(KEY, data) == (1, 0, 0xAABBCCDD, 7, b"hello vpn")


def test_tampered_ciphertext_rejected():
    data = bytearray(encode(KEY, 1, 0, 1, 1, b"secret"))
    data[HEADER_LEN] ^= 1            # flip one bit in the ciphertext
    with pytest.raises(ValueError):
        decode(KEY, bytes(data))


def test_tampered_header_rejected():
    data = bytearray(encode(KEY, 1, 0, 1, 1, b"secret"))
    data[1] ^= 1                     # change key_epoch: header is AAD, so this must fail
    with pytest.raises(ValueError):
        decode(KEY, bytes(data))


def test_wrong_key_rejected():
    data = encode(KEY, 1, 0, 1, 1, b"secret")
    with pytest.raises(ValueError):
        decode(bytes(32), data)
