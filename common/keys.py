"""Turn the handshake result into the two AES keys (one per direction)."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_keys(shared_secret, transcript):
    """Return (c2s_key, s2c_key).

    shared_secret = the X25519 result both sides computed.
    transcript    = every handshake byte sent so far; used as the HKDF salt, so if
                    anyone changed a message, the two sides get different keys.
    The labels "c2s" / "s2c" make the two directions use different keys.
    """
    def one(label):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=transcript,
                    info=label).derive(shared_secret)
    return one(b"c2s"), one(b"s2c")
