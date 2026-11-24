#!/usr/bin/env python3
"""Save a packet capture of one mode's key exchange (Section 11, Stage 3).  Run with sudo, from anywhere.

  sudo python3 lab/capture.py <plain|gre|wireguard|minivpn|openvpn>

It records on router1 (interface eth1, the link every mode crosses) with tshark and writes
  captures/MODE.pcapng           the capture (owned by you, not root)
  captures/MODE.summary.txt      what is inside, worked out with tshark, and a pass/MISSING check list
The order matters, because handshakes happen while the tunnel comes up:
  1. old mode off, netem off   2. tshark starts   3. the mode comes up (lab/switch.py code)
  4. a little traffic from client1   5. tshark stops   6. mode off again (plain lab).
If any step fails it says which one and still stops tshark and switches the mode off.

Why tshark writes into a private folder under /tmp first, and the file is copied to captures/ afterwards:
on Ubuntu 26.04 tshark and its helper dumpcap run under an AppArmor profile (/etc/apparmor.d/tshark). The dumpcap
part gets only the capabilities net_admin and net_raw, so even as root it cannot go through folders it does not
own by normal permissions. Your home folder (mode 750, owned by you) is such a folder, and tshark failed with
"could not be opened: Permission denied". A folder we create under /tmp is owned by root, so it works.
tshark also ends by itself after `-a duration:N`, because a stop signal from this script may be refused by the profile.

The same profile also stops tshark from READING files in your home or project folder (it allows /tmp only), even
when you run it yourself. So the checks and the summary read the private /tmp copy, and they run as the person who
ran sudo (reading needs no root, and tshark warns against running as root). captures/ is only for the final copy.
"""
import argparse
import math
import os
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import switch  # noqa: E402  (same folder; we reuse its Switcher, so cleanup works exactly like `switch.py off`)

CAPTURE_DIR = os.path.join(ROOT, "captures")
NETEM = os.path.join(HERE, "netem.sh")
ROUTER_NS, IFACE = "router1", "eth1"
CLIENT_NS = "client1"
REKEY_SECONDS = 8            # Mini VPN client --rekey-interval while capturing (the normal default is 120 s)
MAX_PACKET_LINES = 60        # packets listed in the summary file
SIGNAL_WAIT = 5              # seconds to wait for tshark after the stop signal

# Per mode: BPF capture filter (what is saved), the ping traffic (count, seconds apart) and the checks.
# A check is (what we expect to see, Wireshark display filter, minimum number of packets).
SPECS = {
    "plain": {
        "bpf": "icmp",
        "bringup": 0,            # seconds the mode may need to come up (the handshake is recorded during this time)
        "ping": (5, 0.5),
        "checks": [("ICMP echo requests", "icmp.type == 8", 5),
                   ("ICMP echo replies", "icmp.type == 0", 5)],
        "conv": ["ip"],
    },
    "gre": {
        "bpf": "ip proto 47",
        "bringup": 5,
        "ping": (5, 0.5),
        "checks": [("GRE packets (IP protocol 47)", "ip.proto == 47", 10),
                   ("ICMP echo requests readable inside GRE", "gre && icmp.type == 8", 5),
                   ("ICMP echo replies readable inside GRE", "gre && icmp.type == 0", 5)],
        "conv": ["ip"],
    },
    "wireguard": {
        "bpf": "udp port 51822",
        "bringup": 5,
        "ping": (10, 0.5),
        "checks": [("handshake initiation (wg.type 1)", "wg.type == 1", 1),
                   ("handshake response (wg.type 2)", "wg.type == 2", 1),
                   ("transport data (wg.type 4)", "wg.type == 4", 10)],
        "conv": ["udp"],
    },
    "minivpn": {
        "bpf": "tcp port 51821 or udp port 51820",
        "bringup": 30,
        "ping": (22, 1.0),       # long enough for at least two rekeys at REKEY_SECONDS
        "checks": [("TCP SYN to port 51821 (handshake starts)",
                    "tcp.dstport == 51821 && tcp.flags.syn == 1 && tcp.flags.ack == 0", 1),
                   ("TCP packets with data on 51821 (handshake, login, rekeys)", "tcp.port == 51821 && tcp.len > 0", 6),
                   ("UDP data packets on 51820", "udp.port == 51820", 20)],
        "conv": ["tcp", "udp"],
    },
    "openvpn": {
        "bpf": "udp port 1194",
        "bringup": 30,
        "ping": (10, 0.5),
        "checks": [("client hard reset (opcode 7)", "openvpn.opcode == 7", 1),
                   ("server hard reset (opcode 8)", "openvpn.opcode == 8", 1),
                   ("control packets, the TLS handshake (opcode 4)", "openvpn.opcode == 4", 2),
                   ("data packets (opcode 9)", "openvpn.opcode == 9", 10)],
        "conv": ["udp"],
    },
}
assert set(SPECS) == set(switch.MODES)      # one spec per mode that switch.py knows


class CaptureError(Exception):
    """One step failed. `step` says which one, `detail` is what we saw."""
    def __init__(self, step, detail=""):
        super().__init__(step)
        self.step = step
        self.detail = detail


# ---------- pure helpers (no root needed, tested in tests/test_capture.py) ----------

def capture_seconds(mode):
    """How long tshark may run before it stops by itself: bring-up allowance + the ping + a margin."""
    return math.ceil(SPECS[mode]["bringup"] + ping_seconds(mode) + 10)


def capture_command(mode, out_path, iface=IFACE, ns=ROUTER_NS):
    """The tshark command that records `mode` on router1 (and stops by itself after capture_seconds)."""
    return ["ip", "netns", "exec", ns, "tshark", "-n", "-i", iface, "-f", SPECS[mode]["bpf"],
            "-a", f"duration:{capture_seconds(mode)}", "-F", "pcapng", "-w", out_path]


def ping_command(mode):
    count, interval = SPECS[mode]["ping"]
    return ["ip", "netns", "exec", CLIENT_NS, "ping", "-n", "-c", str(count), "-i", str(interval), "-W", "3",
            switch.MODES[mode]["target"]]


def ping_seconds(mode):
    count, interval = SPECS[mode]["ping"]
    return count * interval


def count_lines(text):
    """Number of non-empty lines (tshark -T fields prints one line per matching packet)."""
    return sum(1 for line in text.splitlines() if line.strip())


def evaluate_checks(counts, checks):
    """counts: {display filter: packets found}. Returns one dict per check with an `ok` flag."""
    return [{"label": label, "filter": flt, "found": counts.get(flt, 0), "needed": need,
             "ok": counts.get(flt, 0) >= need} for label, flt, need in checks]


def count_rekeys(client_log_text):
    """How many 'rekeyed, now epoch N' lines the Mini VPN client printed."""
    return sum(1 for line in client_log_text.splitlines() if "rekeyed, now epoch" in line)


def format_summary(mode, info, results, sections):
    """The text of captures/MODE.summary.txt. info: dict of facts, results: evaluate_checks(), sections: [(title, text)]."""
    lines = [f"Capture summary: {mode}", "=" * 60,
             f"file:            {info['file']}",
             f"size:            {info['size']} bytes",
             f"packets:         {info['packets']}",
             f"recorded on:     {ROUTER_NS} {IFACE} (the router link)",
             f"capture filter:  {SPECS[mode]['bpf']}",
             f"traffic:         ping from {CLIENT_NS} to {switch.MODES[mode]['target']}, "
             f"{SPECS[mode]['ping'][0]} packets, {SPECS[mode]['ping'][1]:g} s apart",
             f"date:            {info['date']}"]
    lines += [f"note:            {n}" for n in info.get("notes", [])]
    lines += ["", "Checks (does the file contain what we expect?)", "-" * 60]
    for r in results:
        lines.append(f"[{'ok' if r['ok'] else 'MISSING'}] {r['label']}: found {r['found']}, need at least "
                     f"{r['needed']}   (display filter: {r['filter']})")
    for title, text in sections:
        lines += ["", title, "-" * 60, text.rstrip()]
    return "\n".join(lines) + "\n"


# ---------- tshark helpers ----------

def reader_identity():
    """(uid, gid, home) of the person who ran sudo, or None (not run through sudo)."""
    try:
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
        return uid, gid, pwd.getpwuid(uid).pw_dir
    except (KeyError, ValueError):
        return None


def read_kwargs():
    """subprocess.run options so that read-side tshark runs as the person who ran sudo (never as root if we can help it)."""
    who = reader_identity()
    if who is None:
        return {}
    uid, gid, home = who
    kw = {"user": uid, "group": gid, "env": {**os.environ, "HOME": home}}
    if os.geteuid() == 0:
        kw["extra_groups"] = []                 # drop root's other groups too
    return kw


def tshark_read(pcap, *args):
    """Run `tshark -n -r pcap ...` (as the person who ran sudo). Returns the output text, or raises CaptureError."""
    argv = ["tshark", "-n", "-r", pcap] + list(args)
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60, **read_kwargs())
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CaptureError("read the capture with tshark", f"{' '.join(argv)}: {e}")
    if p.returncode != 0:
        raise CaptureError("read the capture with tshark", f"{' '.join(argv)}: {(p.stderr or p.stdout).strip()[-300:]}")
    return p.stdout


def count_matches(pcap, display_filter):
    out = tshark_read(pcap, "-Y", display_filter, "-T", "fields", "-e", "frame.number")
    return count_lines(out)


def build_sections(mode, pcap, client_log=""):
    """Extra text for the summary. A failing tshark call becomes a line of text, it never stops the summary."""
    def safe(title, *args):
        try:
            return title, tshark_read(pcap, *args)
        except CaptureError as e:
            return title, f"(tshark failed: {e.detail})"
    sections = [safe("Protocol hierarchy (tshark -z io,phs)", "-q", "-z", "io,phs")]
    for kind in SPECS[mode]["conv"]:
        sections.append(safe(f"Conversations ({kind})", "-q", "-z", f"conv,{kind}"))
    if mode == "minivpn":
        title, text = safe("TCP packets with data on port 51821 (handshake first, then one pair per rekey)",
                           "-Y", "tcp.port == 51821 && tcp.len > 0", "-T", "fields", "-E", "header=y",
                           "-e", "frame.number", "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst",
                           "-e", "tcp.len")
        sections.append((title, text))
        sections.append(("Client log: rekeys", f"{count_rekeys(client_log)} line(s) 'rekeyed, now epoch N' in the "
                                                f"Mini VPN client log (rekey every {REKEY_SECONDS} s)"))
    sections.append(safe(f"First {MAX_PACKET_LINES} packets (tshark's one-line view)", "-c", str(MAX_PACKET_LINES)))
    return sections


# ---------- the capture ----------

def own_files(path):
    """Give a file or folder back to the person who ran sudo (we run as root)."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid and os.path.exists(path):
        try:
            os.chown(path, int(uid), int(gid))
        except OSError as e:
            print(f"warning: could not change the owner of {path}: {e}")


def run_step(step, argv, timeout):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise CaptureError(step, f"no answer after {timeout:g} s: {' '.join(argv)}")
    except OSError as e:
        raise CaptureError(step, str(e))
    if p.returncode != 0:
        raise CaptureError(step, ((p.stdout + p.stderr).strip()[-300:]) or f"exit code {p.returncode}")
    return p.stdout


class Capture:
    def __init__(self, mode, say=print):
        self.mode, self.say = mode, say
        self.messages = []                                    # what switch.py code printed (shown only on failure)
        self.sw = switch.Switcher(say=self.messages.append)
        self.proc = None
        self.pcap = os.path.join(CAPTURE_DIR, f"{mode}.pcapng")      # the final file
        self.work_dir = None                                  # private folder under /tmp where tshark writes
        self.work_pcap = None
        self.err_path = None

    def make_work_dir(self):
        self.work_dir = tempfile.mkdtemp(prefix="minivpn-capture-")           # mode 700, owned by root
        self.work_pcap = os.path.join(self.work_dir, f"{self.mode}.pcapng")
        self.err_path = os.path.join(self.work_dir, "tshark.log")

    def start_tshark(self):
        """Start tshark and make sure it really is recording: the file exists and tshark is still running a moment
        later. (tshark prints 'Capturing on' even when it then cannot open the file, so that line proves nothing.)"""
        self.make_work_dir()
        with open(self.err_path, "wb") as err:
            self.proc = subprocess.Popen(capture_command(self.mode, self.work_pcap), stdin=subprocess.DEVNULL,
                                         stdout=err, stderr=subprocess.STDOUT, start_new_session=True)
        end = time.time() + 15
        while not os.path.exists(self.work_pcap):
            if self.proc.poll() is not None or time.time() > end:
                raise CaptureError("start tshark on router1", self.tshark_says() or "no output")
            time.sleep(0.1)
        time.sleep(1.0)                                       # a failure to write shows up right after the file appears
        if self.proc.poll() is not None:
            raise CaptureError("start tshark on router1", self.tshark_says() or "tshark stopped at once")

    def tshark_says(self):
        return " ".join(l.strip() for l in switch.read_text(self.err_path).strip().splitlines()
                        if "could be dangerous" not in l and "This could be dangerous" not in l)[-400:]

    def stop_tshark(self, patience=SIGNAL_WAIT, wait_for_limit=True):
        """Ask tshark to stop (Ctrl+C), then wait. If the signal is refused or ignored, wait for the
        `-a duration` limit: tshark ends by itself (not when we are cleaning up after a failure). Safe to call twice."""
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            os.killpg(proc.pid, signal.SIGINT)
        except OSError:
            pass                                              # refused (AppArmor) or already gone
        try:
            proc.wait(timeout=patience)
            return
        except subprocess.TimeoutExpired:
            pass
        if wait_for_limit:
            self.say(f"  - tshark did not stop at the signal; waiting for its own time limit "
                     f"(at most {capture_seconds(self.mode)} s after it started)")
        try:
            proc.wait(timeout=capture_seconds(self.mode) + 10 if wait_for_limit else 2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.say("  - warning: tshark is still running. Stop it by hand: sudo pkill -f 'tshark.*-w'")

    def bring_up(self):
        if self.mode == "minivpn":
            self.sw.minivpn_client_args = ["--rekey-interval", str(REKEY_SECONDS)]
        if self.sw.switch_to(self.mode) != 0:
            raise CaptureError(f"bring up mode {self.mode}", " | ".join(self.messages[-6:]))

    def run(self):
        s = self.say
        s(f"Capturing '{self.mode}' on {ROUTER_NS} {IFACE}  (filter: {SPECS[self.mode]['bpf']})")
        run_step("remove network impairment (netem.sh off)", [NETEM, "off"], 30)
        if self.sw.teardown():
            time.sleep(1)                                     # let the old tunnel's packets stop
        s("  - start tshark")
        self.start_tshark()
        s(f"  - bring up {self.mode} (its handshake is recorded)")
        self.bring_up()
        secs = ping_seconds(self.mode)
        s(f"  - generate traffic: ping from {CLIENT_NS}, about {secs:g} s")
        run_step(f"ping from {CLIENT_NS} to {switch.MODES[self.mode]['target']}", ping_command(self.mode), secs + 30)
        time.sleep(1)
        s("  - stop tshark")
        self.stop_tshark()
        s("  - mode off (back to the plain lab)")
        self.sw.teardown()
        self.save_file()
        self.hand_over_work_files()

    def save_file(self):
        """Copy the capture from the private /tmp folder into captures/ and give it to the person who ran sudo."""
        if not (self.work_pcap and os.path.exists(self.work_pcap) and os.path.getsize(self.work_pcap) > 0):
            raise CaptureError("find the capture file", f"tshark wrote no file. tshark said: "
                               f"{self.tshark_says() or '(nothing)'}")
        os.makedirs(CAPTURE_DIR, exist_ok=True)
        shutil.copyfile(self.work_pcap, self.pcap)
        own_files(CAPTURE_DIR)
        own_files(self.pcap)

    def hand_over_work_files(self):
        """tshark has stopped. Give the private /tmp folder and the capture to the person who ran sudo, so the
        read-side tshark (which runs as that person) can open it."""
        who = reader_identity()
        if who is None or not self.work_dir:
            return
        for path in (self.work_dir, self.work_pcap):
            if path and os.path.exists(path):
                try:
                    os.chown(path, who[0], who[1])
                except OSError as e:
                    raise CaptureError("hand the capture over for reading", f"{path}: {e}")

    def cleanup_files(self):
        if self.work_dir:
            shutil.rmtree(self.work_dir, ignore_errors=True)
            self.work_dir = None

    def finish(self):
        """Read the file, write the summary, print the check list. Returns True if every check passed."""
        if not os.path.exists(self.pcap) or os.path.getsize(self.pcap) == 0:
            raise CaptureError("find the capture file", f"{self.pcap} is missing or empty")
        src = self.work_pcap                              # same bytes, but in /tmp where tshark may read it
        spec = SPECS[self.mode]
        counts = {flt: count_matches(src, flt) for _, flt, _ in spec["checks"]}
        results = evaluate_checks(counts, spec["checks"])
        client_log = (switch.read_text(os.path.join(switch.LOG_DIR, "minivpn-client.log"))
                      if self.mode == "minivpn" else "")
        notes = []
        if self.mode == "minivpn" and count_rekeys(client_log) < 1:
            notes.append("WARNING: the client log shows no rekey, so this file has no rekey exchange. Run it again.")
        info = {"file": os.path.relpath(self.pcap, ROOT), "size": os.path.getsize(self.pcap),
                "packets": count_matches(src, "frame"), "date": time.strftime("%Y-%m-%d %H:%M:%S %z"),
                "notes": notes}
        text = format_summary(self.mode, info, results, build_sections(self.mode, src, client_log))
        summary = os.path.join(CAPTURE_DIR, f"{self.mode}.summary.txt")
        with open(summary, "w") as f:
            f.write(text)
        own_files(summary)
        self.say(f"\n{info['file']}: {info['packets']} packets, {info['size']} bytes")
        for r in results:
            self.say(f"  [{'ok' if r['ok'] else 'MISSING'}] {r['label']}: {r['found']} (need {r['needed']})")
        for n in notes:
            self.say("  " + n)
        self.say(f"Summary: {os.path.relpath(summary, ROOT)}")
        return all(r["ok"] for r in results) and not notes


def main(argv=None):
    ap = argparse.ArgumentParser(prog="capture.py", description="Capture one mode's key exchange. Needs sudo.")
    ap.add_argument("mode", choices=list(SPECS))
    args = ap.parse_args(argv)
    if os.geteuid() != 0:
        print("Run with sudo")
        return 1
    for tool in ("tshark", "ip"):
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            print(f"Missing program: {tool}")
            return 1
    cap = Capture(args.mode)
    rc = 0
    try:
        cap.run()
        if not cap.finish():
            print("Some checks are MISSING (see the summary file). The file is kept, but do not use it as evidence yet.")
            rc = 2
    except CaptureError as e:
        print(f"\nFAILED at step: {e.step}")
        if e.detail:
            print(f"  {e.detail}")
        rc = 1
    except KeyboardInterrupt:
        print("\nInterrupted. Cleaning up.")
        rc = 130
    finally:
        cap.stop_tshark(wait_for_limit=False)
        try:
            cap.sw.teardown()
        except Exception as e:     # cleanup must never hide the real error
            print(f"warning: mode off failed ({e}). Run: sudo python3 lab/switch.py off")
        own_files(CAPTURE_DIR)
        own_files(cap.pcap)
        cap.cleanup_files()
    return rc


if __name__ == "__main__":
    sys.exit(main())
