"""Tests for lab/capture.py that need no root: commands, check logic, summary text, and the display filters
run against small packet files we build here with real tshark (skipped if tshark is not installed)."""
import os
import shutil
import socket
import struct
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lab"))
import capture
import switch

needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark is not installed")


# ---- tiny packet-file builder (classic pcap, Ethernet) ----

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip(src, dst, proto, payload):
    head = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))
    head = head[:10] + struct.pack(">H", checksum(head)) + head[12:]
    return head + payload


def icmp(kind, seq):
    body = struct.pack(">BBHHH", kind, 0, 0, 7, seq) + b"x" * 56
    return body[:2] + struct.pack(">H", checksum(body)) + body[4:]


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, flags, payload=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, flags, 65535, 0, 0) + payload


def frame(ip_packet):
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + ip_packet


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1000 + i, 0, len(fr), len(fr)) + fr)


C, S = "10.0.1.2", "10.0.3.2"


# ---- commands and specs ----

def test_every_mode_has_a_spec_and_checks():
    assert set(capture.SPECS) == set(switch.MODES)
    for spec in capture.SPECS.values():
        assert spec["bpf"] and spec["checks"] and spec["ping"][0] > 0


def test_capture_command_records_on_router1_eth1_into_pcapng():
    argv = capture.capture_command("wireguard", "/x/wireguard.pcapng")
    assert argv[:5] == ["ip", "netns", "exec", "router1", "tshark"]
    assert argv[argv.index("-i") + 1] == "eth1"
    assert argv[argv.index("-f") + 1] == "udp port 51822"
    assert argv[argv.index("-F") + 1] == "pcapng" and argv[-2:] == ["-w", "/x/wireguard.pcapng"]
    assert argv[argv.index("-a") + 1] == f"duration:{capture.capture_seconds('wireguard')}"   # stops by itself


def test_capture_filters_match_the_ports_in_the_brief():
    f = {m: s["bpf"] for m, s in capture.SPECS.items()}
    assert f["minivpn"] == "tcp port 51821 or udp port 51820"
    assert f["wireguard"] == "udp port 51822" and f["openvpn"] == "udp port 1194"
    assert f["gre"] == "ip proto 47" and f["plain"] == "icmp"


def test_ping_goes_to_the_address_switch_py_reports():
    for mode, info in switch.MODES.items():
        argv = capture.ping_command(mode)
        assert argv[:4] == ["ip", "netns", "exec", "client1"] and argv[-1] == info["target"]


def test_minivpn_traffic_lasts_long_enough_for_two_rekeys():
    assert capture.ping_seconds("minivpn") >= 2.5 * capture.REKEY_SECONDS


# ---- check logic and summary text ----

def test_evaluate_checks():
    checks = [("a", "f1", 2), ("b", "f2", 1)]
    r = capture.evaluate_checks({"f1": 2, "f2": 0}, checks)
    assert [x["ok"] for x in r] == [True, False] and r[1]["found"] == 0 and r[0]["needed"] == 2
    assert capture.evaluate_checks({}, checks)[0]["found"] == 0       # a filter that was never counted


def test_count_lines_and_rekeys():
    assert capture.count_lines("1\n2\n\n  \n3\n") == 3
    log = "login OK\nrekeyed, now epoch 1\nrekeyed, now epoch 2\n"
    assert capture.count_rekeys(log) == 2 and capture.count_rekeys("login OK\n") == 0


def test_format_summary():
    results = capture.evaluate_checks({"icmp.type == 8": 5, "icmp.type == 0": 3}, capture.SPECS["plain"]["checks"])
    text = capture.format_summary("plain", {"file": "captures/plain.pcapng", "size": 1234, "packets": 10,
                                            "date": "2026-11-18", "notes": ["a note"]},
                                  results, [("Section title", "body text")])
    for part in ("Capture summary: plain", "captures/plain.pcapng", "capture filter:  icmp", "[ok] ICMP echo requests",
                 "[MISSING] ICMP echo replies", "display filter: icmp.type == 0", "Section title", "body text", "a note"):
        assert part in text


def test_own_files_does_nothing_without_sudo_variables(tmp_path, monkeypatch):
    monkeypatch.delenv("SUDO_UID", raising=False)
    capture.own_files(str(tmp_path))          # must not raise


def test_minivpn_client_args_reach_client_py(tmp_path, monkeypatch):
    sys.path.insert(0, HERE)
    from test_switch import VpnEnv
    env = VpnEnv(tmp_path, monkeypatch)
    env.sw.minivpn_client_args = ["--rekey-interval", str(capture.REKEY_SECONDS)]
    assert env.sw.switch_to("minivpn") == 0
    (_, _, _), (_, cargv, _) = env.spawned
    assert cargv[-5:] == ["alice", "-p", "pw1", "--rekey-interval", str(capture.REKEY_SECONDS)]


# ---- the display filters, with real tshark and small files we build ----

@needs_tshark
def test_every_display_filter_is_valid(tmp_path):
    empty = str(tmp_path / "empty.pcap")
    write_pcap(empty, [])
    for mode, spec in capture.SPECS.items():
        for label, flt, _ in spec["checks"]:
            assert capture.count_matches(empty, flt) == 0, (mode, label)    # raises CaptureError if the filter is bad


@needs_tshark
def test_plain_and_gre_checks_count_the_right_packets(tmp_path):
    plain = [frame(ip(C, S, 1, icmp(8 if i % 2 == 0 else 0, i))) for i in range(10)]          # 5 requests, 5 replies
    path = str(tmp_path / "plain.pcap")
    write_pcap(path, plain)
    r = capture.evaluate_checks({f: capture.count_matches(path, f) for _, f, _ in capture.SPECS["plain"]["checks"]},
                                capture.SPECS["plain"]["checks"])
    assert all(x["ok"] for x in r) and [x["found"] for x in r] == [5, 5]

    def gre(kind, i):                      # outer IP protocol 47, GRE header (no options, protocol 0x0800), inner ICMP
        return frame(ip(C, S, 47, struct.pack(">HH", 0, 0x0800) + ip("10.11.0.2", "10.11.0.1", 1, icmp(kind, i))))
    path = str(tmp_path / "gre.pcap")
    write_pcap(path, [gre(8 if i % 2 == 0 else 0, i) for i in range(10)])
    r = capture.evaluate_checks({f: capture.count_matches(path, f) for _, f, _ in capture.SPECS["gre"]["checks"]},
                                capture.SPECS["gre"]["checks"])
    assert all(x["ok"] for x in r), r
    assert capture.count_matches(path, "icmp") == 10 and capture.count_matches(str(tmp_path / "plain.pcap"), "gre") == 0


@needs_tshark
def test_minivpn_checks_and_sections(tmp_path):
    syn, data, ack = 0x02, 0x18, 0x10
    frames = [frame(ip(C, S, 6, tcp(40000, 51821, syn)))]
    frames += [frame(ip(C if i % 2 == 0 else S, S if i % 2 == 0 else C, 6,
                        tcp(40000, 51821, data, b"y" * 34))) for i in range(8)]      # handshake + a rekey pair or two
    frames += [frame(ip(C, S, 6, tcp(40000, 51821, ack)))]                           # an empty ACK must not count
    frames += [frame(ip(C, S, 17, udp(50000, 51820, b"z" * 114))) for _ in range(22)]
    path = str(tmp_path / "minivpn.pcap")
    write_pcap(path, frames)
    spec = capture.SPECS["minivpn"]
    counts = {f: capture.count_matches(path, f) for _, f, _ in spec["checks"]}
    assert [x["found"] for x in capture.evaluate_checks(counts, spec["checks"])] == [1, 8, 22]
    assert all(x["ok"] for x in capture.evaluate_checks(counts, spec["checks"]))
    assert capture.count_matches(path, "frame") == len(frames)
    titles = dict(capture.build_sections("minivpn", path, "rekeyed, now epoch 1\nrekeyed, now epoch 2\n"))
    assert any("Conversations (tcp)" in t for t in titles) and any("Conversations (udp)" in t for t in titles)
    rekey = next(v for t, v in titles.items() if t.startswith("Client log"))
    assert rekey.startswith("2 line(s)")
    table = next(v for t, v in titles.items() if t.startswith("TCP packets with data"))
    assert "frame.time_relative" in table and "51821" not in table.split("\n")[0]      # header row + one row per packet
    assert len(table.strip().splitlines()) == 1 + 8


@needs_tshark
def test_missing_pieces_are_reported_not_hidden(tmp_path):
    path = str(tmp_path / "plain.pcap")
    write_pcap(path, [frame(ip(C, S, 1, icmp(8, i))) for i in range(5)])             # requests only, no replies
    checks = capture.SPECS["plain"]["checks"]
    r = capture.evaluate_checks({f: capture.count_matches(path, f) for _, f, _ in checks}, checks)
    assert [x["ok"] for x in r] == [True, False]


@needs_tshark
def test_bad_capture_file_raises_a_step_error(tmp_path):
    bad = tmp_path / "bad.pcapng"
    bad.write_bytes(b"not a capture")
    with pytest.raises(capture.CaptureError):
        capture.count_matches(str(bad), "frame")


# ---- the AppArmor / permission fix: tshark writes into a private /tmp folder, then we copy ----

def test_capture_seconds_cover_bringup_and_traffic():
    for mode, spec in capture.SPECS.items():
        assert capture.capture_seconds(mode) >= spec["bringup"] + capture.ping_seconds(mode) + 10
    assert capture.capture_seconds("plain") < capture.capture_seconds("minivpn")


def fake_tshark(monkeypatch, script):
    """Replace the real tshark command by a small shell script; $1 is the output file."""
    monkeypatch.setattr(capture, "capture_command", lambda mode, out: ["sh", "-c", script, "sh", out])


def test_work_dir_is_private_and_under_tmp():
    cap = capture.Capture("plain", say=lambda *_: None)
    cap.make_work_dir()
    try:
        assert os.path.dirname(cap.work_dir) == os.path.realpath(__import__("tempfile").gettempdir())
        assert (os.stat(cap.work_dir).st_mode & 0o777) == 0o700           # only the owner can enter it
        assert cap.work_pcap.endswith("plain.pcapng") and cap.work_pcap.startswith(cap.work_dir)
    finally:
        cap.cleanup_files()
    assert not os.path.exists(cap.work_dir or "/nonexistent-dir")


def test_start_tshark_reports_the_real_error_when_the_file_cannot_be_opened(monkeypatch):
    # what really happened: 'Capturing on' is printed first, then the open fails and tshark exits
    fake_tshark(monkeypatch, "echo 'Running as user root. This could be dangerous.'; echo \"Capturing on 'eth1'\"; "
                             "echo 'tshark: The file could not be opened: Permission denied.' >&2; exit 2")
    cap = capture.Capture("plain", say=lambda *_: None)
    try:
        with pytest.raises(capture.CaptureError) as info:
            cap.start_tshark()
    finally:
        cap.cleanup_files()
    assert info.value.step == "start tshark on router1"
    assert "Permission denied" in info.value.detail and "This could be dangerous" not in info.value.detail


def test_start_tshark_notices_a_failure_just_after_the_file_appears(monkeypatch):
    fake_tshark(monkeypatch, ": > \"$1\"; echo 'tshark: write error: Permission denied' >&2; exit 2")
    cap = capture.Capture("plain", say=lambda *_: None)
    try:
        with pytest.raises(capture.CaptureError) as info:
            cap.start_tshark()
    finally:
        cap.cleanup_files()
    assert "Permission denied" in info.value.detail


def test_stop_tshark_with_a_working_signal_is_quick(monkeypatch):
    fake_tshark(monkeypatch, ": > \"$1\"; exec sleep 30")
    cap = capture.Capture("plain", say=lambda *_: None)
    try:
        cap.start_tshark()
        assert cap.proc.poll() is None                       # really running
        t0 = time.monotonic()
        cap.stop_tshark()
        assert time.monotonic() - t0 < 4 and cap.proc is None
    finally:
        cap.stop_tshark(wait_for_limit=False)
        cap.cleanup_files()


def test_stop_tshark_when_the_signal_is_refused_waits_for_tshark_to_end_by_itself(monkeypatch):
    fake_tshark(monkeypatch, ": > \"$1\"; exec sleep 3")                   # ends by itself after 3 s
    said = []
    cap = capture.Capture("plain", say=said.append)

    def refused(pid, sig):
        raise PermissionError(13, "Permission denied")           # what an AppArmor signal rule gives
    monkeypatch.setattr(capture.os, "killpg", refused)
    try:
        cap.start_tshark()
        t0 = time.monotonic()
        cap.stop_tshark(patience=0.3)                            # must not raise, must wait for the process
        waited = time.monotonic() - t0
    finally:
        monkeypatch.undo()
        cap.stop_tshark(wait_for_limit=False)
        cap.cleanup_files()
    assert 1.0 < waited < 8 and any("waiting for its own time limit" in m for m in said)


def test_save_file_copies_out_of_tmp_into_captures(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "CAPTURE_DIR", str(tmp_path / "captures"))
    cap = capture.Capture("plain", say=lambda *_: None)
    cap.make_work_dir()
    try:
        with open(cap.work_pcap, "wb") as f:
            f.write(b"pcapng bytes")
        monkeypatch.setattr(cap, "pcap", str(tmp_path / "captures" / "plain.pcapng"))
        cap.save_file()
        assert open(cap.pcap, "rb").read() == b"pcapng bytes"
    finally:
        cap.cleanup_files()


def test_save_file_without_a_capture_says_what_tshark_said(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "CAPTURE_DIR", str(tmp_path / "captures"))
    cap = capture.Capture("plain", say=lambda *_: None)
    cap.make_work_dir()
    try:
        open(cap.err_path, "w").write("tshark: could not be opened: Permission denied.\n")
        with pytest.raises(capture.CaptureError) as info:
            cap.save_file()
        assert info.value.step == "find the capture file" and "Permission denied" in info.value.detail
    finally:
        cap.cleanup_files()


# ---- reading the capture: the private /tmp copy, as the person who ran sudo ----

def test_reader_identity_comes_from_the_sudo_variables(monkeypatch):
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    assert capture.reader_identity() is None and capture.read_kwargs() == {}
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))
    monkeypatch.setenv("SUDO_GID", str(os.getgid()))
    uid, gid, home = capture.reader_identity()
    assert (uid, gid) == (os.getuid(), os.getgid()) and os.path.isdir(home)
    monkeypatch.setenv("SUDO_UID", "not-a-number")
    assert capture.reader_identity() is None                        # a broken value is ignored, not a crash


def test_read_kwargs_run_tshark_as_that_person_and_drop_root_groups(monkeypatch):
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))
    monkeypatch.setenv("SUDO_GID", str(os.getgid()))
    kw = capture.read_kwargs()
    assert kw["user"] == os.getuid() and kw["group"] == os.getgid() and "extra_groups" not in kw   # not root here
    assert kw["env"]["HOME"] == capture.reader_identity()[2]
    monkeypatch.setattr(capture.os, "geteuid", lambda: 0)            # as under sudo
    assert capture.read_kwargs()["extra_groups"] == []


@needs_tshark
def test_tshark_read_works_with_the_sudo_variables_set(tmp_path, monkeypatch):
    monkeypatch.setenv("SUDO_UID", str(os.getuid()))
    monkeypatch.setenv("SUDO_GID", str(os.getgid()))
    path = str(tmp_path / "p.pcap")                                  # under /tmp, where tshark's profile allows reading
    write_pcap(path, [frame(ip(C, S, 1, icmp(8, i))) for i in range(3)])
    assert capture.count_matches(path, "icmp.type == 8") == 3


def test_hand_over_chowns_the_work_files_only_when_run_through_sudo(monkeypatch):
    cap = capture.Capture("plain", say=lambda *_: None)
    cap.make_work_dir()
    try:
        open(cap.work_pcap, "wb").write(b"x")
        monkeypatch.delenv("SUDO_UID", raising=False)
        cap.hand_over_work_files()                                   # no sudo: nothing to do
        calls = []
        monkeypatch.setenv("SUDO_UID", str(os.getuid()))
        monkeypatch.setenv("SUDO_GID", str(os.getgid()))
        monkeypatch.setattr(capture.os, "chown", lambda path, uid, gid: calls.append((path, uid, gid)))
        cap.hand_over_work_files()
        assert [c[0] for c in calls] == [cap.work_dir, cap.work_pcap]
        assert all(c[1:] == (os.getuid(), os.getgid()) for c in calls)
    finally:
        monkeypatch.undo()
        cap.cleanup_files()


@needs_tshark
def test_finish_reads_the_tmp_copy_not_the_file_in_captures(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "CAPTURE_DIR", str(tmp_path / "captures"))
    cap = capture.Capture("plain", say=lambda *_: None)
    cap.make_work_dir()
    try:
        write_pcap(cap.work_pcap, [frame(ip(C if i % 2 == 0 else S, S if i % 2 == 0 else C, 1, icmp(8 if i % 2 == 0 else 0, i)))
                                   for i in range(10)])
        monkeypatch.setattr(cap, "pcap", str(tmp_path / "captures" / "plain.pcapng"))
        cap.save_file()
        read_from = set()
        real_read = capture.tshark_read

        def spy(pcap, *args):
            read_from.add(pcap)
            return real_read(pcap, *args)
        monkeypatch.setattr(capture, "tshark_read", spy)
        assert cap.finish() is True                                  # all checks ok on the 10 crafted ICMP packets
        assert read_from == {cap.work_pcap}                          # never the copy in captures/
        summary = (tmp_path / "captures" / "plain.summary.txt").read_text()
        assert "[ok] ICMP echo requests" in summary and "packets:         10" in summary
        assert "captures" in summary.split("file:")[1].splitlines()[0]    # the summary names the FINAL file
    finally:
        cap.cleanup_files()
