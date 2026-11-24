import json
import os
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from common.packet import TYPE_DATA, TYPE_KEEPALIVE, encode
from common.packetlog import MAX_PACKETS, PacketLog, decode_header, describe_inner
from dashboard.app import create_app

SERVER = ("10.0.3.2", 51820)
CLIENT = ("10.0.1.2", 40000)
SECRET = b"TOP-SECRET-PAYLOAD-BYTES"


def ip_packet(src="10.8.0.2", dst="10.8.0.1", proto=1, payload=SECRET):
    head = bytes([0x45, 0, 0, 0]) + bytes(4) + bytes([64, proto, 0, 0]) + socket.inet_aton(src) + socket.inet_aton(dst)
    return head + payload


def test_header_is_decoded_and_short_packets_have_none():
    wire = encode(b"k" * 32, TYPE_DATA, 3, 77, 12345, b"x")
    assert decode_header(wire) == {"type": "data", "session_id": 77, "key_epoch": 3, "counter": 12345}
    assert decode_header(b"short") is None


def test_inner_packet_protocols():
    assert describe_inner(ip_packet(proto=1)) == {"src": "10.8.0.2", "dst": "10.8.0.1", "protocol": "ICMP", "size": 20 + len(SECRET)}
    assert describe_inner(ip_packet(proto=6))["protocol"] == "TCP"
    assert describe_inner(ip_packet(proto=17))["protocol"] == "UDP"
    assert describe_inner(ip_packet(proto=47))["protocol"] == "proto 47"
    assert describe_inner(b"") is None and describe_inner(b"\x60" + bytes(40)) is None    # empty, IPv6


def test_accepted_and_dropped_rows():
    log = PacketLog(SERVER)
    plain = ip_packet()
    wire = encode(b"k" * 32, TYPE_DATA, 1, 5, 9, plain)
    log.received(CLIENT, wire, None, plain, now=100.0)
    log.received(CLIENT, wire, "replay", plain, now=101.0)
    log.received(CLIENT, b"junk" * 10, "unknown session", now=102.0)
    log.sent(CLIENT, wire, plain, now=103.0)
    rows = log.snapshot(now=104.0)["packets"]
    assert [r["time"] for r in rows] == [103.0, 102.0, 101.0, 100.0]                  # newest first
    sent, unknown, replay, ok = rows
    assert ok["direction"] == "client to server" and ok["result"] == "accepted" and ok["reason"] is None
    assert ok["outer"] == {"src_ip": "10.0.1.2", "src_port": 40000, "dst_ip": "10.0.3.2", "dst_port": 51820, "size": len(wire)}
    assert ok["header"] == {"type": "data", "session_id": 5, "key_epoch": 1, "counter": 9}
    assert ok["inner"]["src"] == "10.8.0.2" and ok["inner"]["protocol"] == "ICMP"
    assert replay["result"] == "dropped" and replay["reason"] == "replay"
    assert unknown["reason"] == "unknown session" and unknown["inner"] is None
    assert sent["direction"] == "server to client" and sent["outer"]["src_port"] == 51820 and sent["outer"]["dst_port"] == 40000


def test_keepalive_has_no_inner_packet():
    log = PacketLog(SERVER)
    wire = encode(b"k" * 32, TYPE_KEEPALIVE, 0, 5, 1, b"")
    log.received(CLIENT, wire, None, b"")
    row = log.snapshot()["packets"][0]
    assert row["header"]["type"] == "keepalive" and row["inner"] is None


def test_only_the_last_20_are_kept():
    log = PacketLog(SERVER)
    for i in range(MAX_PACKETS + 7):
        log.received(CLIENT, encode(b"k" * 32, TYPE_DATA, 0, 1, i, b"x"), "bad tag", now=float(i))
    rows = log.snapshot()["packets"]
    assert len(rows) == MAX_PACKETS and rows[0]["header"]["counter"] == MAX_PACKETS + 6


def test_no_payload_or_key_bytes_are_stored():
    log = PacketLog(SERVER)
    key = b"K" * 32
    plain = ip_packet()
    wire = encode(key, TYPE_DATA, 1, 5, 9, plain)
    log.received(CLIENT, wire, None, plain)
    text = json.dumps(log.snapshot())
    assert SECRET.decode() not in text and SECRET.hex() not in text
    assert key.decode() not in text and key.hex() not in text
    assert wire.hex() not in text and plain.hex() not in text
    assert set(log.snapshot()["packets"][0]) == {"time", "direction", "outer", "header", "inner", "result", "reason"}


def test_write_is_atomic_once_a_second_and_leaves_no_temp_file(tmp_path):
    log, path = PacketLog(SERVER), tmp_path / "packets.json"
    log.received(CLIENT, b"x" * 30, "bad tag")
    assert log.maybe_write(str(path)) is True
    assert log.maybe_write(str(path)) is False                    # too soon
    assert json.loads(path.read_text())["packets"][0]["reason"] == "bad tag"
    assert os.listdir(tmp_path) == ["packets.json"]


def test_api_packets_fresh_missing_and_stale(tmp_path):
    path = tmp_path / "packets.json"
    client = create_app(str(tmp_path / "stats.json"), str(tmp_path / "x.csv")).test_client()   # packets file defaults next to stats
    assert client.get("/api/packets").get_json() == {"running": False}                          # missing: "no packets yet"
    log = PacketLog(SERVER)
    log.received(CLIENT, b"x" * 30, "bad tag")
    log.maybe_write(str(path))
    got = client.get("/api/packets").get_json()
    assert got["running"] is True and got["packets"][0]["reason"] == "bad tag"
    data = json.loads(path.read_text())
    data["server_time"] -= 60                                                                   # old file
    path.write_text(json.dumps(data))
    assert client.get("/api/packets").get_json() == {"running": False}
    assert client.get("/static/packets.js").status_code == 200
