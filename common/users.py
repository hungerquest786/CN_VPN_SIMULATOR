"""User passwords (Section 4). We never store a password, only a scrypt hash.
Each user gets their own random salt, so two users with the same password get different hashes.
users.json looks like: {"alice": {"salt": "<hex>", "hash": "<hex>"}}
"""
import hashlib
import hmac
import json
import os

N, R, P = 2**14, 8, 1        # scrypt cost settings (slow on purpose, to make guessing hard)


def _scrypt(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=N, r=R, p=P)


def load_users(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def add_user(path, name, password):
    """Add (or replace) a user and save the file."""
    users = load_users(path)
    salt = os.urandom(16)
    users[name] = {"salt": salt.hex(), "hash": _scrypt(password, salt).hex()}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # only the owner can read
    with os.fdopen(fd, "w") as f:
        json.dump(users, f, indent=2)


def check_password(users, name, password):
    """True only if the user exists and the password is right.
    For an unknown user we still run scrypt, so it takes the same time either way."""
    rec = users.get(name)
    salt = bytes.fromhex(rec["salt"]) if rec else bytes(16)
    expected = bytes.fromhex(rec["hash"]) if rec else bytes(32)
    same = hmac.compare_digest(_scrypt(password, salt), expected)
    return rec is not None and same
