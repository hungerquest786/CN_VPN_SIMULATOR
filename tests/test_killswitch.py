import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from common.killswitch import TABLE, rules_text


def accepts(text):
    return [l.strip() for l in text.splitlines() if l.strip().endswith("accept")]


def test_default_is_drop_on_outgoing_traffic():
    t = rules_text()
    assert "hook output" in t and "policy drop" in t
    assert "hook input" not in t and "hook forward" not in t   # we only filter what we send


def test_exactly_the_allowed_traffic_is_accepted():
    assert accepts(rules_text()) == [
        'oifname "lo" accept',
        'oifname "tun0" accept',
        "ip daddr 10.0.3.2 udp dport 51820 accept",
        "ip daddr 10.0.3.2 tcp dport 51821 accept",
    ]


def test_server_address_and_ports_follow_the_arguments():
    t = rules_text(server_ip="192.0.2.9", udp_port=1, tcp_port=2)
    assert "ip daddr 192.0.2.9 udp dport 1 accept" in t
    assert "ip daddr 192.0.2.9 tcp dport 2 accept" in t
    assert "10.0.3.2" not in t


def test_only_our_own_named_table_is_touched():
    t = rules_text()
    tables = set(re.findall(r"table (?:inet|ip|ip6) (\w+)", t))
    assert tables == {TABLE} == {"minivpn_ks"}
    assert "flush ruleset" not in t
    assert "inet" in t                                          # IPv6 is blocked too
