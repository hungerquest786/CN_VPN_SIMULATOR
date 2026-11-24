"""Temporary key handling for Section 2 (a shared key file, no handshake yet)."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def load_psk(path="psk.key"):
    # The pre-shared key is 32 random bytes stored in a file.
    with open(path, "rb") as f:
        psk = f.read()
    if len(psk) != 32:
        raise SystemExit("psk.key must be exactly 32 bytes")
    return psk


def derive_keys(psk):
    """Return (c2s_key, s2c_key): one AES-256 key for each direction."""
    def one(label):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=label).derive(psk)
    return one(b"c2s"), one(b"s2c")
