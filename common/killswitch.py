"""Client kill switch (Section 8): an nft firewall table that blocks everything that is not the tunnel.

The table has its own name, so deleting it never touches any other rule.
Only OUTGOING packets are filtered. Default is drop; these are allowed:
  - loopback (lo)
  - anything leaving through tun0 (that is the tunnel)
  - UDP 51820 and TCP 51821 to the real VPN server address (so the tunnel can connect)
It is IPv4 and IPv6 ("inet"), so nothing leaks through IPv6 either.
"""
import subprocess

TABLE = "minivpn_ks"


def rules_text(server_ip="10.0.3.2", udp_port=51820, tcp_port=51821, tun="tun0"):
    # "add" then "delete" first: this makes sure an old copy of our table is gone, in one step.
    return f"""
add table inet {TABLE}
delete table inet {TABLE}
table inet {TABLE} {{
    chain output {{
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        oifname "{tun}" accept
        ip daddr {server_ip} udp dport {udp_port} accept
        ip daddr {server_ip} tcp dport {tcp_port} accept
    }}
}}
"""


def install(**kw):
    """Turn the kill switch on (run inside the client's namespace)."""
    subprocess.run(["nft", "-f", "-"], input=rules_text(**kw).encode(), check=True)


def release():
    """Turn it off. Removes only our own table. Returns True if it was there."""
    r = subprocess.run(["nft", "delete", "table", "inet", TABLE], capture_output=True)
    return r.returncode == 0
