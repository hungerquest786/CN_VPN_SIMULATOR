"""Build and parse one VPN packet.

Packet layout (all numbers big-endian):
    header (14 bytes) = type(1) + key_epoch(1) + session_id(4) + seq(8)
    ciphertext        = the encrypted IP packet
    tag (16 bytes)    = GCM tag, added at the end by AES-GCM
The header is NOT encrypted, but it is signed (AAD), so changing it breaks the tag.
"""
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HEADER_FMT = ">BBIQ"                      # 1 + 1 + 4 + 8 bytes
HEADER_LEN = struct.calcsize(HEADER_FMT)  # = 14
TAG_LEN = 16
TYPE_DATA = 1                             # type 1 = normal data packet
TYPE_REKEY = 4                            # type 4 = rekey message (only on the TCP connection)
TYPE_KEEPALIVE = 3                        # type 3 = keepalive (empty payload), the server answers it
TYPE_LOGIN = 2                            # type 2 = login message (only on the TCP connection)


def make_nonce(session_id, seq):
    # Nonce (12 bytes) = session_id (4 bytes) + seq (8 bytes).
    # It must never repeat with the same key, so seq goes up by 1 every packet.
    return struct.pack(">IQ", session_id, seq)


def encode(key, ptype, epoch, session_id, seq, plaintext):
    """Encrypt plaintext and return header + ciphertext + tag."""
    header = struct.pack(HEADER_FMT, ptype, epoch, session_id, seq)
    nonce = make_nonce(session_id, seq)
    # AESGCM.encrypt returns ciphertext with the 16-byte tag already attached.
    return header + AESGCM(key).encrypt(nonce, plaintext, header)


def decode(key, data):
    """Check and decrypt a packet. Raises ValueError if it is bad or tampered."""
    if len(data) < HEADER_LEN + TAG_LEN:
        raise ValueError("packet too short")
    header = data[:HEADER_LEN]
    ptype, epoch, session_id, seq = struct.unpack(HEADER_FMT, header)
    nonce = make_nonce(session_id, seq)
    try:
        # The header is passed as AAD, so if anyone changed it, this fails.
        plaintext = AESGCM(key).decrypt(nonce, data[HEADER_LEN:], header)
    except Exception:
        raise ValueError("bad tag: packet was changed or key is wrong")
    return ptype, epoch, session_id, seq, plaintext
