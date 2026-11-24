#!/usr/bin/env python3
"""Switch the lab between VPN modes (Section 10).  Run with sudo, from anywhere.

  sudo python3 lab/switch.py <plain|minivpn|wireguard|openvpn|gre>
  sudo python3 lab/switch.py status
  sudo python3 lab/switch.py off

Test path is always client1 -> router1 -> router2 -> serverA.  Only one mode is active at a time.
Everything we create is written to a state file (lab/.switch/state.json) together with the command
that undoes it.  "off", a mode change and a failed step all use that same undo list.
lab/netem.sh is not touched: it shapes the router link, which every mode crosses.
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(HERE, ".switch")      # gitignored: state file and logs
MTU = 1400                                      # same tunnel MTU as the Mini VPN
ROOT = os.path.dirname(HERE)                    # the project folder (the Mini VPN is started from here)
LOG_DIR = os.path.join(STATE_DIR, "logs")       # background processes write their output here
STATS_FILE = os.path.join(ROOT, "stats.json")   # where the Mini VPN server writes numbers for the dashboard
VPN_USER, VPN_PASSWORD = "alice", "pw1"         # the test user from our earlier sections
# WireGuard config files (they hold the private keys). Must be under /etc/wireguard: Ubuntu's AppArmor
# profile for /usr/bin/wg refuses any other place, even for root. Outside the project, so never in git.
WG_DIR = "/etc/wireguard/minivpn-lab"
# OpenVPN: our own CA and certificates, new ones at every switch. No AppArmor profile limits where they live.
PKI_DIR = os.path.join(STATE_DIR, "openvpn-pki")
OVPN_PORT = 1194
OVPN_DEV = "ovpn0"                              # not tun0, so it never clashes with the Mini VPN
WG_PORT = 51822                                 # WireGuard UDP port on serverA

CLIENT_NS = "client1"
SERVER_NS = "serverA"
CLIENT_REAL = "10.0.1.2"
SERVER_REAL = "10.0.3.2"
NAMESPACES = ["client1", "client2", "client3", "router1", "router2", "serverA", "serverB"]

# net = tunnel network, target = the address Section 11 pings and runs iperf3 against (serverA = .1)
MODES = {
    "plain":     {"net": None,           "target": SERVER_REAL},
    "minivpn":   {"net": "10.8.0.0/24",  "target": "10.8.0.1"},
    "wireguard": {"net": "10.9.0.0/24",  "target": "10.9.0.1"},
    "openvpn":   {"net": "10.10.0.0/24", "target": "10.10.0.1"},
    "gre":       {"net": "10.11.0.0/24", "target": "10.11.0.1"},
}
COMMANDS = list(MODES) + ["status", "off"]


class StepError(Exception):
    """One step failed. `step` says which one, `detail` is what the command printed."""
    def __init__(self, step, detail=""):
        super().__init__(step)
        self.step = step
        self.detail = detail


def run_cmd(argv, input=None):
    """Run a command. Returns (exit code, output). Never raises for a non-zero exit."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, input=input)
    except FileNotFoundError:
        return 127, f"{argv[0]}: command not found"
    return p.returncode, (p.stdout + p.stderr).strip()


def read_text(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def tail(path, n=6):
    return " | ".join(read_text(path).strip().splitlines()[-n:])


def spawn_process(argv, log_path, cwd=None):
    """Start a background process in its own session, output to a log file. Returns the pid."""
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "wb") as log:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                             cwd=cwd, start_new_session=True)
    return p.pid


def process_alive(pid, match):
    """True if `pid` is a running process whose command line contains `match` (so a reused pid is not ours)."""
    try:
        os.waitpid(pid, os.WNOHANG)          # if it is our own child that ended, collect it
    except (ChildProcessError, OSError):
        pass
    try:
        cmdline = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace")
        state = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return False
    return state != "Z" and match in cmdline


def stop_process(pid, match, wait=5.0):
    """SIGTERM, wait up to `wait` seconds, then SIGKILL. Returns a short word for the output."""
    if not process_alive(pid, match):
        return "already gone"
    os.kill(pid, signal.SIGTERM)
    end = time.time() + wait
    while time.time() < end:
        if not process_alive(pid, match):
            return "stopped"
        time.sleep(0.1)
    os.kill(pid, signal.SIGKILL)
    time.sleep(0.3)
    process_alive(pid, match)
    return f"did not stop in {wait:g}s, killed"


def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="switch.py",
        description="Switch the lab between VPN modes. Needs sudo.")
    ap.add_argument("command", choices=COMMANDS,
                    help="a mode to switch to, 'status' to show the active mode, or 'off' to go back to the plain lab")
    return ap.parse_args(argv)


# ---------- state file ----------

class State:
    """What is active, and how to undo it. Saved after every step, so a crash can still be cleaned up."""
    def __init__(self, state_dir=STATE_DIR):
        self.dir = state_dir
        self.path = os.path.join(state_dir, "state.json")

    def load(self):
        try:
            with open(self.path) as f:
                return json.load(f)
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            return {"mode": "unknown (state file unreadable)", "undo": [], "interfaces": [], "ready": False}

    def save(self, data):
        os.makedirs(self.dir, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)

    def clear(self):
        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass


def link_is_up(ip_output):
    """True if `ip -o link show` output says the interface has the UP flag."""
    m = re.search(r"<([^>]*)>", ip_output)
    return bool(m) and "UP" in m.group(1).split(",")


def wg_conf(private_key, peer_public_key, allowed_ips, listen_port=None, endpoint=None):
    """Text for `wg setconf`. Default WireGuard crypto (Curve25519, ChaCha20-Poly1305), nothing to choose."""
    lines = ["[Interface]", f"PrivateKey = {private_key}"]
    if listen_port:
        lines.append(f"ListenPort = {listen_port}")
    lines += ["", "[Peer]", f"PublicKey = {peer_public_key}", f"AllowedIPs = {allowed_ips}"]
    if endpoint:
        lines.append(f"Endpoint = {endpoint}")
    return "\n".join(lines) + "\n"


def openvpn_conf(role, pki, mtu=MTU):
    """Text of the OpenVPN config for 'server' or 'client'. Same settings on both sides except the role lines."""
    lines = [
        "# generated by lab/switch.py: do not edit",
        f"dev {OVPN_DEV}", "dev-type tun", "proto udp",
        f"tun-mtu {mtu}",            # same tunnel MTU as every other mode
        "mssfix 0",                  # no TCP size clamping, the other modes have none
        "disable-dco",               # classic userspace OpenVPN (the kernel offload is not used)
        "data-ciphers AES-256-GCM",  # only this cipher: no fallback to anything else
        "cipher AES-256-GCM",
        "tls-version-min 1.2",
        f"ca {pki}/ca.crt", f"cert {pki}/{role}.crt", f"key {pki}/{role}.key",
        "verb 3",
    ]
    if role == "server":
        lines += [f"local {SERVER_REAL}", f"port {OVPN_PORT}", "server 10.10.0.0 255.255.255.0",
                  "topology subnet", "keepalive 10 60", "dh none", "remote-cert-tls client"]
    else:
        lines += ["client", f"remote {SERVER_REAL} {OVPN_PORT}", "nobind", "remote-cert-tls server"]
    return "\n".join(lines) + "\n"


# ---------- the switcher ----------

class Switcher:
    def __init__(self, state=None, runner=run_cmd, say=print):
        self.state = state or State()
        self.run = runner
        self.say = say
        self.data = None
        # these four can be replaced in tests
        self.spawn, self.stop, self.alive, self.sleep = spawn_process, stop_process, process_alive, time.sleep

    # --- building blocks ---
    def step(self, text, argv, undo=None, quiet_undo=False):
        """Print what we do, run it, remember how to undo it."""
        self.say(f"  - {text}")
        code, out = self.run(argv)
        if code != 0:
            raise StepError(text, out)
        if undo:
            item = {"text": f"undo: {text}", "argv": undo}
            if quiet_undo:
                item["quiet"] = True     # no message if it fails (it is only a safety net)
            self.data["undo"].append(item)
            self.state.save(self.data)

    def start_process(self, label, ns, args, python=True, match=None):
        """Start a program inside namespace `ns` in the background (python3 -u args... if python=True);
        remember how to stop it. `match` is a word that must be in its command line for us to stop it later."""
        log = os.path.join(LOG_DIR, f"{self.data['mode']}-{label}.log")
        argv = ["ip", "netns", "exec", ns] + ([sys.executable, "-u"] if python else []) + args
        self.say(f"  - start {label} in {ns} (log: {os.path.relpath(log, ROOT)})")
        try:
            pid = self.spawn(argv, log, ROOT)
        except OSError as e:
            raise StepError(f"start {label} in {ns}", str(e))
        match = match or os.path.basename(args[0])
        self.data.setdefault("processes", []).append({"name": label, "pid": pid, "match": match})
        self.data["undo"].append({"text": f"undo: stop {label} (pid {pid})",
                                  "kill": {"pid": pid, "match": match}})
        self.state.save(self.data)
        return pid, match, log

    def wait_until(self, text, check, pid, match, log, timeout=15.0):
        """Wait for check() to be true. Stop early with the log if the process died."""
        end = time.time() + timeout
        while True:
            if check():
                return
            if not self.alive(pid, match):
                raise StepError(text, f"the process stopped. Log: {tail(log) or '(empty)'}")
            if time.time() > end:
                raise StepError(text, f"not ready after {timeout:g}s. Log: {tail(log) or '(empty)'}")
            self.sleep(0.2)

    def link_up(self, ns, name):
        code, out = self.run(["ip", "-n", ns, "-o", "link", "show", "dev", name])
        return code == 0 and link_is_up(out)

    def ip(self, text, ns, *args, undo_args=None):
        argv = ["ip"] + (["-n", ns] if ns else []) + list(args)
        undo = None
        if undo_args:
            undo = ["ip"] + (["-n", ns] if ns else []) + list(undo_args)
        self.step(text, argv, undo)

    def ensure_dir(self, folder):
        """Make `folder` (mode 700) and any missing parents; remember to remove only the ones we made."""
        missing, d = [], folder
        while not os.path.isdir(d):
            missing.append(d)
            d = os.path.dirname(d)
        try:
            for d in reversed(missing):       # parent first
                os.mkdir(d, 0o700)
                self.data["undo"].append({"text": f"undo: create folder {d}", "argv": ["rmdir", d]})
                self.state.save(self.data)
        except OSError as e:
            raise StepError(f"create folder {d}", str(e))

    def write_file(self, text, path, text_label):
        """Write a secret file (mode 600) and remember to delete it (and any folder we had to create)."""
        self.say(f"  - write {text_label}")
        self.ensure_dir(os.path.dirname(path))
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(text)
        except OSError as e:
            raise StepError(f"write {text_label}", str(e))
        self.data["undo"].append({"text": f"undo: write {text_label}", "argv": ["rm", "-f", path]})
        self.state.save(self.data)

    # --- tear down ---
    def teardown(self):
        """Undo everything the state file lists, newest first. Returns the mode that was removed (or None)."""
        data = self.state.load()
        if data is None:
            return None
        mode = data.get("mode")
        self.say(f"Stopping mode '{mode}':")
        for item in reversed(data.get("undo", [])):
            if "kill" in item:
                k = item["kill"]
                self.say(f"  - {item['text']} -> {self.stop(k['pid'], k['match'])}")
                continue
            code, out = self.run(item["argv"])
            if code == 0:
                self.say(f"  - {item['text']}")
            elif item.get("quiet"):
                pass
            else:   # usually "already gone": keep going, the rest still has to be removed
                self.say(f"  - {item['text']} -> skipped ({out or 'failed'})")
        self.state.clear()
        return mode

    # --- bring up ---
    def preflight(self):
        code, out = self.run(["ip", "netns", "list"])
        names = {line.split()[0] for line in out.splitlines() if line.strip()}
        missing = [ns for ns in NAMESPACES if ns not in names]
        if code != 0 or missing:
            raise StepError("check that the lab exists",
                            f"missing namespaces: {', '.join(missing) or 'all'}. Run: sudo ./lab/setup.sh")

    def switch_to(self, mode):
        """Tear down the active mode, then bring up `mode`. Returns 0 if it worked."""
        old = self.teardown()
        if old:
            self.say("")
        info = MODES[mode]
        self.data = {"mode": mode, "target": info["target"], "net": info["net"],
                     "interfaces": [], "undo": [], "ready": False}
        self.say(f"Switching to '{mode}':")
        try:
            self.preflight()
            self.state.save(self.data)
            getattr(self, "up_" + mode)()
        except StepError as e:
            self.say(f"ERROR: this step failed: {e.step}")
            if e.detail:
                self.say(f"       {e.detail}")
            self.say("Cleaning up what was already done:")
            self.teardown()
            return 1
        self.data["ready"] = True
        self.state.save(self.data)
        self.say(f"Mode '{mode}' is up. Test target: {info['target']}")
        return 0

    # --- the modes ---
    def up_plain(self):
        self.say("  - no tunnel: the target is serverA's real address")

    def up_gre(self):
        self.say("  GRE: NO ENCRYPTION. Packets are only wrapped (protocol 47, no UDP choice).")
        self.say("  It shows the cost of tunnelling alone.")
        ends = [(CLIENT_NS, CLIENT_REAL, SERVER_REAL, "10.11.0.2/24"),
                (SERVER_NS, SERVER_REAL, CLIENT_REAL, "10.11.0.1/24")]
        for ns, local, remote, addr in ends:
            self.ip(f"{ns}: create gre1 ({local} -> {remote})", ns,
                    "link", "add", "gre1", "type", "gre", "local", local, "remote", remote, "ttl", "64",
                    undo_args=["link", "del", "gre1"])
            self.data["interfaces"].append([ns, "gre1"])
            self.state.save(self.data)
            self.ip(f"{ns}: address {addr}", ns, "addr", "add", addr, "dev", "gre1")
            self.ip(f"{ns}: MTU {MTU}, bring up", ns, "link", "set", "gre1", "mtu", str(MTU), "up")

    def up_wireguard(self):
        self.say("  WireGuard: default crypto, UDP port %d, new keys made now (kept in %s)." % (WG_PORT, WG_DIR))
        keys = {}
        for who in ("client", "server"):
            self.say(f"  - generate {who} key pair")
            code, priv = self.run(["wg", "genkey"])
            if code != 0 or not priv:
                raise StepError(f"generate {who} private key (wg genkey)", priv)
            code, pub = self.run(["wg", "pubkey"], input=priv + "\n")
            if code != 0 or not pub:
                raise StepError(f"generate {who} public key (wg pubkey)", pub)
            keys[who] = (priv, pub)
        conf = {
            "client": wg_conf(keys["client"][0], keys["server"][1], "10.9.0.1/32",
                              endpoint=f"{SERVER_REAL}:{WG_PORT}"),
            "server": wg_conf(keys["server"][0], keys["client"][1], "10.9.0.2/32", listen_port=WG_PORT),
        }
        paths = {who: os.path.join(WG_DIR, f"wg-{who}.conf") for who in conf}
        for who in conf:
            self.write_file(conf[who], paths[who], f"{who} config {paths[who]}")
        ends = [("client", CLIENT_NS, "10.9.0.2/24"), ("server", SERVER_NS, "10.9.0.1/24")]
        for who, ns, addr in ends:
            self.ip(f"{ns}: create wg0", ns, "link", "add", "wg0", "type", "wireguard",
                    undo_args=["link", "del", "wg0"])
            self.data["interfaces"].append([ns, "wg0"])
            self.state.save(self.data)
            self.step(f"{ns}: load {who} config into wg0",
                      ["ip", "netns", "exec", ns, "wg", "setconf", "wg0", paths[who]])
            self.ip(f"{ns}: address {addr}", ns, "addr", "add", addr, "dev", "wg0")
            self.ip(f"{ns}: MTU {MTU}, bring up", ns, "link", "set", "wg0", "mtu", str(MTU), "up")

    def up_minivpn(self):
        self.say("  Mini VPN: our own server (in serverA) and client (in client1), AES-256-GCM,")
        self.say(f"  UDP 51820 for data, TCP 51821 for the handshake. User {VPN_USER}.")
        # 1. things the Mini VPN needs
        missing = [f for f in ("certs/ca.pub", "certs/server.cert", "certs/server.key", "users.json")
                   if not os.path.exists(os.path.join(ROOT, f))]
        if missing:
            raise StepError("check the Mini VPN files", f"missing: {', '.join(missing)}. See NOTES.md Sections 3 and 4 "
                            f"(tools/ca.py init, tools/ca.py issue vpn-server, tools/users.py add {VPN_USER})")
        try:
            with open(os.path.join(ROOT, "users.json")) as f:
                known = VPN_USER in json.load(f)
        except (OSError, ValueError):
            known = False
        if not known:
            raise StepError(f"check user {VPN_USER}", f"not in users.json. Run: python3 tools/users.py add {VPN_USER}")
        # 2. tun0 is exclusive: refuse if one is already there (for example a Mini VPN started by hand)
        for ns in (SERVER_NS, CLIENT_NS):
            code, _ = self.run(["ip", "-n", ns, "link", "show", "dev", "tun0"])
            if code == 0:
                raise StepError(f"check that tun0 is free in {ns}",
                                "tun0 already exists there. Stop the Mini VPN you started by hand (Ctrl-C), then try again")
        # 3. the server turns on ip_forward and a NAT rule in serverA; put both back when we stop
        code, fwd = self.run(["ip", "netns", "exec", SERVER_NS, "cat", "/proc/sys/net/ipv4/ip_forward"])
        if code == 0 and fwd.strip() == "0":
            self.data["undo"].append({"text": "undo: serverA ip_forward back to 0",
                                      "argv": ["ip", "netns", "exec", SERVER_NS, "sysctl", "-qw", "net.ipv4.ip_forward=0"]})
        self.data["undo"].append({"text": "undo: remove NAT table minivpn_nat in serverA (safety net)", "quiet": True,
                                  "argv": ["ip", "netns", "exec", SERVER_NS, "nft", "delete", "table", "ip", "minivpn_nat"]})
        self.state.save(self.data)
        # 4. server, then client
        pid, match, log = self.start_process("server", SERVER_NS,
                                             [os.path.join(ROOT, "server", "server.py"), "--stats-file", STATS_FILE])
        self.say("  - wait for the server to be ready")
        self.wait_until("the Mini VPN server becomes ready", lambda: "server up" in read_text(log), pid, match, log)
        self.data["interfaces"].append([SERVER_NS, "tun0"])
        pid, match, log = self.start_process("client", CLIENT_NS,
                                             [os.path.join(ROOT, "client", "client.py"), VPN_USER, "-p", VPN_PASSWORD])
        self.say("  - wait for the client to log in (its tun0 appears)")
        self.wait_until("the Mini VPN client logs in", lambda: self.link_up(CLIENT_NS, "tun0"), pid, match, log)
        self.data["interfaces"].append([CLIENT_NS, "tun0"])
        self.state.save(self.data)

    def up_openvpn(self):
        self.say("  OpenVPN: our own CA and certificates (new at every switch), AES-256-GCM, UDP %d," % OVPN_PORT)
        self.say(f"  userspace (DCO off), tunnel MTU {MTU}, TCP size clamping (mssfix) off. Files: {os.path.relpath(PKI_DIR, ROOT)}")
        for ns in (SERVER_NS, CLIENT_NS):
            code, _ = self.run(["ip", "-n", ns, "link", "show", "dev", OVPN_DEV])
            if code == 0:
                raise StepError(f"check that {OVPN_DEV} is free in {ns}",
                                f"{OVPN_DEV} already exists there. Stop the OpenVPN you started by hand, then try again")
        # 1. certificates: CA, then a server and a client certificate signed by it
        self.ensure_dir(PKI_DIR)
        made = [os.path.join(PKI_DIR, f) for f in ("ca.crt", "ca.key", "ca.srl", "server.key", "server.csr",
                "server.crt", "client.key", "client.csr", "client.crt")]
        self.data["undo"].append({"text": "undo: delete the OpenVPN keys and certificates", "argv": ["rm", "-f"] + made})
        self.state.save(self.data)
        pki = PKI_DIR
        ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
        self.step("make the CA (ECDSA P-256, valid 30 days)",
                  ["openssl", "req", "-x509"] + ec + ["-keyout", f"{pki}/ca.key", "-out", f"{pki}/ca.crt",
                   "-subj", "/CN=minivpn-lab-ca", "-days", "30", "-addext", "basicConstraints=critical,CA:TRUE",
                   "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        for role, usage in (("server", "serverAuth"), ("client", "clientAuth")):
            self.write_file(f"basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage={usage}\n",
                            f"{pki}/{role}.ext", f"{role} certificate rules")
            self.step(f"make the {role} key and certificate request",
                      ["openssl", "req", "-new"] + ec + ["-keyout", f"{pki}/{role}.key", "-out", f"{pki}/{role}.csr",
                       "-subj", f"/CN=openvpn-{role}"])
            self.step(f"sign the {role} certificate with our CA",
                      ["openssl", "x509", "-req", "-in", f"{pki}/{role}.csr", "-CA", f"{pki}/ca.crt",
                       "-CAkey", f"{pki}/ca.key", "-CAcreateserial", "-out", f"{pki}/{role}.crt", "-days", "30",
                       "-extfile", f"{pki}/{role}.ext"])
        # 2. configs
        for role in ("server", "client"):
            self.write_file(openvpn_conf(role, pki), f"{pki}/{role}.conf", f"{role} config {pki}/{role}.conf")
        # 3. server, then client
        pid, match, log = self.start_process("server", SERVER_NS, ["openvpn", "--config", f"{pki}/server.conf"],
                                             python=False, match="server.conf")
        self.say("  - wait for the server to be ready")
        done = "Initialization Sequence Completed"
        self.wait_until("the OpenVPN server becomes ready", lambda: done in read_text(log), pid, match, log)
        self.data["interfaces"].append([SERVER_NS, OVPN_DEV])
        pid, match, log = self.start_process("client", CLIENT_NS, ["openvpn", "--config", f"{pki}/client.conf"],
                                             python=False, match="client.conf")
        self.say("  - wait for the client to connect (TLS handshake, then its tunnel appears)")
        self.wait_until("the OpenVPN client connects",
                        lambda: done in read_text(log) and self.link_up(CLIENT_NS, OVPN_DEV), pid, match, log)
        self.data["interfaces"].append([CLIENT_NS, OVPN_DEV])
        self.state.save(self.data)

    # --- status ---
    def status(self):
        data = self.state.load()
        if data is None:
            self.say("active mode: plain (nothing switched on)")
            self.say(f"target IP:   {MODES['plain']['target']}")
            self.say("tunnel up:   n/a (no tunnel)")
            return 0
        mode = data.get("mode")
        self.say(f"active mode: {mode}")
        self.say(f"target IP:   {data.get('target', '?')}")
        if data.get("net"):
            self.say(f"tunnel net:  {data['net']}")
        if mode == "gre":
            self.say("WARNING:     GRE has NO ENCRYPTION (cost of tunnelling alone)")
        problems = []
        if not data.get("ready"):
            problems.append("setup did not finish")
        for ns, name in data.get("interfaces", []):
            code, out = self.run(["ip", "-n", ns, "-o", "link", "show", "dev", name])
            if code != 0:
                problems.append(f"{name} missing in {ns}")
            elif not link_is_up(out):
                problems.append(f"{name} in {ns} is down")
        for p in data.get("processes", []):
            alive = self.alive(p["pid"], p["match"])
            self.say(f"process:     {p['name']} pid {p['pid']} " + ("running" if alive else "NOT RUNNING"))
            if not alive:
                problems.append(f"{p['name']} process is not running")
        if mode == "plain":
            self.say("tunnel up:   n/a (no tunnel)")
        else:
            self.say("tunnel up:   " + ("yes" if not problems else "NO (" + "; ".join(problems) + ")"))
        if data.get("target"):
            code, _ = self.run(["ip", "netns", "exec", CLIENT_NS, "ping", "-c", "1", "-W", "2", data["target"]])
            self.say(f"ping {CLIENT_NS} -> {data['target']}: " + ("reply" if code == 0 else "no reply"))
        return 0 if not problems else 1


def main(argv=None):
    args = parse_args(argv)
    if os.geteuid() != 0:
        print("Run with sudo")
        return 1
    sw = Switcher()
    if args.command == "status":
        return sw.status()
    if args.command == "off":
        if sw.teardown() is None:
            print("Nothing to turn off: already the plain lab.")
        else:
            print("Back to the plain lab.")
        return 0
    return sw.switch_to(args.command)


if __name__ == "__main__":
    sys.exit(main())
