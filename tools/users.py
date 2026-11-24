"""Add a user.   Usage: python3 tools/users.py add USERNAME [PASSWORD]
If you leave out the password, it asks for it (hidden)."""
import getpass
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common.users import add_user

if len(sys.argv) not in (3, 4) or sys.argv[1] != "add":
    sys.exit(__doc__)
password = sys.argv[3] if len(sys.argv) == 4 else getpass.getpass("Password: ")
add_user("users.json", sys.argv[2], password)
print(f"user {sys.argv[2]!r} saved in users.json")
