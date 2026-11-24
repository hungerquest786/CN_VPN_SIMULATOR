"""Mini certificate authority (CA). Run from the project folder:

    python3 tools/ca.py init                 make the CA key pair
    python3 tools/ca.py issue vpn-server     make a server key + certificate

Files go into certs/:
    ca.key       CA private key        SECRET, only used here, not in git
    ca.pub       CA public key         the client reads this to trust the server
    server.key   server private key    SECRET, not in git
    server.cert  server certificate     public
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from common.handshake import make_cert, raw

CERTS = "certs"


def save_private(path, key):
    with open(path, "wb") as f:
        f.write(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    os.chmod(path, 0o600)           # only the owner may read it


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    issue = sub.add_parser("issue")
    issue.add_argument("name")
    issue.add_argument("--days", type=int, default=365)
    args = p.parse_args()
    os.makedirs(CERTS, exist_ok=True)

    if args.cmd == "init":
        ca = Ed25519PrivateKey.generate()
        save_private(f"{CERTS}/ca.key", ca)
        with open(f"{CERTS}/ca.pub", "wb") as f:
            f.write(raw(ca.public_key()))
        print("made certs/ca.key (secret) and certs/ca.pub")
    else:
        with open(f"{CERTS}/ca.key", "rb") as f:
            ca = Ed25519PrivateKey.from_private_bytes(f.read())
        server = Ed25519PrivateKey.generate()
        save_private(f"{CERTS}/server.key", server)
        expiry = int(time.time()) + args.days * 86400
        with open(f"{CERTS}/server.cert", "wb") as f:
            f.write(make_cert(ca, args.name, raw(server.public_key()), expiry))
        print(f"made certs/server.key (secret) and certs/server.cert for {args.name!r}, {args.days} days")


main()
