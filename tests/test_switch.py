"""Tests for lab/switch.py parts that need no root: arguments, state file, undo list, command lists."""
import os
import shutil
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lab"))
import switch


class FakeRunner:
    """Records every command. Fails (exit 1) on the Nth call if fail_at is set."""
    def __init__(self, fail_at=None):
        self.calls = []
        self.fail_at = fail_at

    def __call__(self, argv, input=None):
        self.calls.append(argv)
        if argv[:2] == ["wg", "genkey"]:
            return 0, "PRIVKEY"
        if argv[:2] == ["wg", "pubkey"]:
            return 0, "PUBKEY-of-" + input.strip()
        if argv[:3] == ["ip", "netns", "list"]:
            return 0, "\n".join(switch.NAMESPACES)
        if self.fail_at is not None and len(self.calls) == self.fail_at:
            return 1, "boom"
        return 0, ""


def make(tmp_path, runner):
    out = []
    sw = switch.Switcher(state=switch.State(str(tmp_path)), runner=runner, say=out.append)
    return sw, out


# ---- arguments ----

@pytest.mark.parametrize("cmd", ["plain", "minivpn", "wireguard", "openvpn", "gre", "status", "off"])
def test_valid_commands(cmd):
    assert switch.parse_args([cmd]).command == cmd


@pytest.mark.parametrize("bad", [[], ["ipsec"], ["gre", "extra"]])
def test_bad_arguments_are_refused(bad):
    with pytest.raises(SystemExit):
        switch.parse_args(bad)


def test_tunnel_networks_and_targets():
    nets = {m: i["net"] for m, i in switch.MODES.items()}
    assert nets == {"plain": None, "minivpn": "10.8.0.0/24", "wireguard": "10.9.0.0/24",
                    "openvpn": "10.10.0.0/24", "gre": "10.11.0.0/24"}
    assert switch.MODES["plain"]["target"] == "10.0.3.2"
    for m in ("minivpn", "wireguard", "openvpn", "gre"):   # serverA is always .1
        assert switch.MODES[m]["target"] == switch.MODES[m]["net"].replace("0/24", "1")


# ---- state file ----

def test_state_roundtrip_and_clear(tmp_path):
    st = switch.State(str(tmp_path / "sub"))
    assert st.load() is None
    st.save({"mode": "gre", "undo": []})
    assert st.load()["mode"] == "gre"
    st.clear()
    st.clear()   # twice is fine
    assert st.load() is None


def test_unreadable_state_file_is_still_cleaned(tmp_path):
    st = switch.State(str(tmp_path))
    (tmp_path / "state.json").write_text("{not json")
    assert st.load()["undo"] == []


def test_link_is_up():
    assert switch.link_is_up("5: gre1: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1400 qdisc noqueue")
    assert not switch.link_is_up("5: gre1: <POINTOPOINT,NOARP> mtu 1400 qdisc noqueue")
    assert not switch.link_is_up("")


# ---- gre ----

def test_gre_commands(tmp_path):
    r = FakeRunner()
    sw, out = make(tmp_path, r)
    assert sw.switch_to("gre") == 0
    cmds = [" ".join(c) for c in r.calls]
    assert "ip -n client1 link add gre1 type gre local 10.0.1.2 remote 10.0.3.2 ttl 64" in cmds
    assert "ip -n serverA link add gre1 type gre local 10.0.3.2 remote 10.0.1.2 ttl 64" in cmds
    assert "ip -n client1 addr add 10.11.0.2/24 dev gre1" in cmds
    assert "ip -n serverA addr add 10.11.0.1/24 dev gre1" in cmds
    assert "ip -n client1 link set gre1 mtu 1400 up" in cmds
    assert any("NO ENCRYPTION" in line for line in out)
    data = switch.State(str(tmp_path)).load()
    assert data["ready"] and data["target"] == "10.11.0.1"
    assert data["interfaces"] == [["client1", "gre1"], ["serverA", "gre1"]]


def test_off_undoes_in_reverse_and_clears_state(tmp_path):
    r = FakeRunner()
    sw, _ = make(tmp_path, r)
    sw.switch_to("gre")
    r.calls.clear()
    assert sw.teardown() == "gre"
    assert r.calls == [["ip", "-n", "serverA", "link", "del", "gre1"],
                       ["ip", "-n", "client1", "link", "del", "gre1"]]
    assert switch.State(str(tmp_path)).load() is None
    assert sw.teardown() is None   # second time: nothing to do


def test_switch_twice_tears_down_first(tmp_path):
    r = FakeRunner()
    sw, out = make(tmp_path, r)
    sw.switch_to("gre")
    r.calls.clear()
    assert sw.switch_to("gre") == 0
    first_two = [" ".join(c) for c in r.calls[:2]]
    assert first_two == ["ip -n serverA link del gre1", "ip -n client1 link del gre1"]
    assert len(switch.State(str(tmp_path)).load()["undo"]) == 2   # not doubled


def test_failed_step_cleans_up_what_was_done(tmp_path):
    # calls: 1 netns list, 2 client1 link add (ok), 3 client1 addr add (ok), 4 client1 link set (ok),
    #        5 serverA link add (FAILS)
    r = FakeRunner(fail_at=5)
    sw, out = make(tmp_path, r)
    assert sw.switch_to("gre") == 1
    assert any("this step failed: serverA: create gre1" in line for line in out)
    assert ["ip", "-n", "client1", "link", "del", "gre1"] in r.calls
    assert ["ip", "-n", "serverA", "link", "del", "gre1"] not in r.calls   # never created
    assert switch.State(str(tmp_path)).load() is None


def test_missing_lab_stops_before_changing_anything(tmp_path):
    def runner(argv):
        return (0, "client1") if argv[:3] == ["ip", "netns", "list"] else (0, "")
    sw, out = make(tmp_path, runner)
    assert sw.switch_to("gre") == 1
    assert any("setup.sh" in line for line in out)
    assert switch.State(str(tmp_path)).load() is None


def test_plain_has_nothing_to_undo(tmp_path):
    sw, _ = make(tmp_path, FakeRunner())
    assert sw.switch_to("plain") == 0
    data = switch.State(str(tmp_path)).load()
    assert data["target"] == "10.0.3.2" and data["undo"] == []


# ---- status ----

def test_status_without_state(tmp_path):
    sw, out = make(tmp_path, FakeRunner())
    assert sw.status() == 0
    assert out[0].startswith("active mode: plain") and "10.0.3.2" in out[1]


def test_status_reports_missing_interface(tmp_path):
    r = FakeRunner()
    sw, out = make(tmp_path, r)
    sw.switch_to("gre")
    out.clear()
    def runner(argv):
        if "link" in argv and "show" in argv:
            return 1, "does not exist"
        return 0, ""
    sw.run = runner
    assert sw.status() == 1
    assert any("tunnel up:   NO" in line and "gre1 missing in client1" in line for line in out)


# ---- wireguard ----

def test_wg_conf_client_and_server():
    c = switch.wg_conf("CPRIV", "SPUB", "10.9.0.1/32", endpoint="10.0.3.2:51822")
    assert "PrivateKey = CPRIV" in c and "PublicKey = SPUB" in c
    assert "AllowedIPs = 10.9.0.1/32" in c and "Endpoint = 10.0.3.2:51822" in c
    assert "ListenPort" not in c
    s = switch.wg_conf("SPRIV", "CPUB", "10.9.0.2/32", listen_port=51822)
    assert "ListenPort = 51822" in s and "Endpoint" not in s


@pytest.fixture
def wg_env(tmp_path, monkeypatch):
    monkeypatch.setattr(switch, "WG_DIR", str(tmp_path / "etc" / "wg"))
    return tmp_path


def test_wireguard_commands_and_files(wg_env):
    r = FakeRunner()
    sw, out = make(wg_env, r)
    assert sw.switch_to("wireguard") == 0
    cmds = [" ".join(c) for c in r.calls]
    kd = str(wg_env / "etc" / "wg")
    assert "ip -n client1 link add wg0 type wireguard" in cmds
    assert "ip -n serverA link add wg0 type wireguard" in cmds
    assert f"ip netns exec client1 wg setconf wg0 {kd}/wg-client.conf" in cmds
    assert f"ip netns exec serverA wg setconf wg0 {kd}/wg-server.conf" in cmds
    assert "ip -n client1 addr add 10.9.0.2/24 dev wg0" in cmds
    assert "ip -n serverA addr add 10.9.0.1/24 dev wg0" in cmds
    assert "ip -n serverA link set wg0 mtu 1400 up" in cmds
    for name in ("wg-client.conf", "wg-server.conf"):
        p = wg_env / "etc" / "wg" / name
        assert oct(p.stat().st_mode & 0o777) == "0o600"
    assert "Endpoint = 10.0.3.2:51822" in (wg_env / "etc" / "wg" / "wg-client.conf").read_text()
    assert switch.State(str(wg_env)).load()["target"] == "10.9.0.1"


def test_wireguard_off_removes_interfaces_then_key_files(wg_env):
    r = FakeRunner()
    sw, _ = make(wg_env, r)
    sw.switch_to("wireguard")
    r.calls.clear()
    # run the rm entries for real, the ip entries through the fake
    real = switch.run_cmd
    sw.run = lambda argv, input=None: real(argv) if argv[0] in ("rm", "rmdir") else r(argv)
    sw.teardown()
    cmds = [" ".join(c) for c in r.calls]
    assert cmds == ["ip -n serverA link del wg0", "ip -n client1 link del wg0"]
    assert not (wg_env / "etc").exists()     # the folders we created are gone too


def test_wireguard_failure_removes_key_files(wg_env):
    # fail the first "wg setconf" call
    class F(FakeRunner):
        def __call__(self, argv, input=None):
            if "setconf" in argv:
                self.calls.append(argv)
                return 1, "bad config"
            return super().__call__(argv, input)
    r = F()
    sw, out = make(wg_env, r)
    real = switch.run_cmd
    inner = sw.run
    sw.run = lambda argv, input=None: real(argv) if argv[0] in ("rm", "rmdir") else inner(argv, input)
    assert sw.switch_to("wireguard") == 1
    assert any("load client config into wg0" in line for line in out)
    assert ["ip", "-n", "client1", "link", "del", "wg0"] in r.calls
    assert not list((wg_env / "etc" / "wg").glob("*.conf"))
    assert switch.State(str(wg_env)).load() is None


def test_wg_config_folder_is_where_apparmor_allows():
    # Ubuntu's AppArmor profile for /usr/bin/wg only allows files under /etc/wireguard/
    assert switch.WG_DIR.startswith("/etc/wireguard/")
    assert not switch.WG_DIR.startswith(switch.HERE)   # and never inside the project (git)


def test_existing_config_folder_is_not_removed(wg_env):
    (wg_env / "etc" / "wg").mkdir(parents=True)
    (wg_env / "etc" / "wg" / "mine.conf").write_text("keep")
    r = FakeRunner()
    sw, _ = make(wg_env, r)
    sw.switch_to("wireguard")
    undo = [i["argv"] for i in sw.state.load()["undo"]]
    assert not any(a[0] == "rmdir" for a in undo)        # we did not create the folder, so we do not remove it
    sw.run = lambda argv, input=None: switch.run_cmd(argv) if argv[0] in ("rm", "rmdir") else r(argv)
    sw.teardown()
    assert (wg_env / "etc" / "wg" / "mine.conf").exists()   # a file that is not ours is untouched
    assert not (wg_env / "etc" / "wg" / "wg-client.conf").exists()


# ---- minivpn (wrapper around our own server and client) ----

UP_LINK = "7: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1400 qdisc pfifo_fast"


class VpnEnv:
    """A fake project folder, fake processes and a fake `ip` that knows when client1's tun0 exists."""
    def __init__(self, tmp_path, monkeypatch, tun_busy=False, client_dies=False):
        self.root = tmp_path / "proj"
        (self.root / "certs").mkdir(parents=True)
        for f in ("ca.pub", "server.cert", "server.key"):
            (self.root / "certs" / f).write_text("x")
        (self.root / "users.json").write_text('{"alice": {}}')
        monkeypatch.setattr(switch, "ROOT", str(self.root))
        monkeypatch.setattr(switch, "LOG_DIR", str(tmp_path / "logs"))
        monkeypatch.setattr(switch, "STATS_FILE", str(self.root / "stats.json"))
        self.tun_busy, self.client_dies = tun_busy, client_dies
        self.spawned, self.stopped, self.calls = [], [], []
        self.client_started = False
        sw, self.out = make(tmp_path, self.runner)
        sw.spawn, sw.stop, sw.alive, sw.sleep = self.spawn, self.stop, self.alive, lambda s: None
        self.sw = sw

    def runner(self, argv, input=None):
        self.calls.append(argv)
        if argv[:3] == ["ip", "netns", "list"]:
            return 0, "\n".join(switch.NAMESPACES)
        if argv[-4:-1] == ["link", "show", "dev"] or argv[-3:-1] == ["show", "dev"]:
            if argv[2] == "client1" and "-o" in argv:        # the "is it up" check after login
                return (0, UP_LINK) if self.client_started else (1, "")
            return (0, UP_LINK) if self.tun_busy else (1, "does not exist")   # the "is tun0 free" check
        if argv[-1] == "/proc/sys/net/ipv4/ip_forward":
            return 0, "0"
        return 0, ""

    def spawn(self, argv, log, cwd):
        pid = 100 + len(self.spawned)
        self.spawned.append((pid, argv, cwd))
        os.makedirs(os.path.dirname(log), exist_ok=True)
        if "server.py" in argv[-3] or "server.py" in " ".join(argv):
            open(log, "w").write("server up: UDP ('10.0.3.2', 51820), TCP ('10.0.3.2', 51821)\n")
        else:
            self.client_started = not self.client_dies
            open(log, "w").write("login FAILED\n" if self.client_dies else "login OK\n")
        return pid

    def alive(self, pid, match):
        return not (self.client_dies and pid == 101)

    def stop(self, pid, match):
        self.stopped.append(pid)
        return "stopped"


def test_minivpn_starts_server_then_client(tmp_path, monkeypatch):
    env = VpnEnv(tmp_path, monkeypatch)
    assert env.sw.switch_to("minivpn") == 0
    (spid, sargv, scwd), (cpid, cargv, _) = env.spawned
    assert sargv[:5] == ["ip", "netns", "exec", "serverA", sys.executable]
    assert sargv[-3].endswith(os.path.join("server", "server.py"))
    assert sargv[-2:] == ["--stats-file", str(env.root / "stats.json")]     # the dashboard keeps working
    assert cargv[:4] == ["ip", "netns", "exec", "client1"]
    assert cargv[-3:] == ["alice", "-p", "pw1"] and cargv[-4].endswith(os.path.join("client", "client.py"))
    assert scwd == str(env.root)                                           # certs/ and users.json are found
    data = switch.State(str(tmp_path)).load()
    assert data["ready"] and data["target"] == "10.8.0.1"
    assert [p["name"] for p in data["processes"]] == ["server", "client"]
    assert data["interfaces"] == [["serverA", "tun0"], ["client1", "tun0"]]


def test_minivpn_stop_order_client_first_then_server_then_safety_nets(tmp_path, monkeypatch):
    env = VpnEnv(tmp_path, monkeypatch)
    env.sw.switch_to("minivpn")
    env.calls.clear()
    assert env.sw.teardown() == "minivpn"
    assert env.stopped == [101, 100]                                       # client, then server
    cmds = [" ".join(c) for c in env.calls]
    assert cmds == ["ip netns exec serverA nft delete table ip minivpn_nat",
                    "ip netns exec serverA sysctl -qw net.ipv4.ip_forward=0"]
    assert switch.State(str(tmp_path)).load() is None


def test_minivpn_missing_files_stop_before_starting_anything(tmp_path, monkeypatch):
    env = VpnEnv(tmp_path, monkeypatch)
    (env.root / "certs" / "server.cert").unlink()
    assert env.sw.switch_to("minivpn") == 1
    assert any("server.cert" in line for line in env.out) and env.spawned == []


def test_minivpn_unknown_user_stops(tmp_path, monkeypatch):
    env = VpnEnv(tmp_path, monkeypatch)
    (env.root / "users.json").write_text('{"bob": {}}')
    assert env.sw.switch_to("minivpn") == 1
    assert any("users.py add alice" in line for line in env.out) and env.spawned == []


def test_minivpn_refuses_when_tun0_is_taken(tmp_path, monkeypatch):
    env = VpnEnv(tmp_path, monkeypatch, tun_busy=True)
    assert env.sw.switch_to("minivpn") == 1
    assert any("tun0 is free in serverA" in line for line in env.out) and env.spawned == []


def test_minivpn_client_failure_stops_the_server_too(tmp_path, monkeypatch):
    env = VpnEnv(tmp_path, monkeypatch, client_dies=True)
    assert env.sw.switch_to("minivpn") == 1
    assert any("client logs in" in line for line in env.out)
    assert any("login FAILED" in line for line in env.out)                 # the log tail is shown
    assert 100 in env.stopped                                              # the server we started is stopped
    assert switch.State(str(tmp_path)).load() is None


def test_status_flags_a_dead_process(tmp_path, monkeypatch):
    env = VpnEnv(tmp_path, monkeypatch)
    env.sw.switch_to("minivpn")
    env.out.clear()
    env.sw.alive = lambda pid, match: pid != 100
    assert env.sw.status() == 1
    assert any("server pid 100 NOT RUNNING" in line for line in env.out)
    assert any(line.startswith("tunnel up:   NO") for line in env.out)


def test_quiet_undo_prints_nothing_when_it_fails(tmp_path):
    st = switch.State(str(tmp_path))
    st.save({"mode": "x", "undo": [{"text": "undo: safety", "argv": ["false"], "quiet": True},
                                   {"text": "undo: loud", "argv": ["false"]}]})
    out = []
    sw = switch.Switcher(state=st, runner=lambda argv, input=None: (1, "nope"), say=out.append)
    sw.teardown()
    assert not any("safety" in line for line in out) and any("loud -> skipped" in line for line in out)


# ---- real background processes (no root needed) ----

def test_spawn_logs_to_file_and_stop_process_stops_it(tmp_path):
    log = str(tmp_path / "logs" / "p.log")
    pid = switch.spawn_process(["sh", "-c", "echo hello; exec sleep 60"], log)
    try:
        for _ in range(50):
            if "hello" in switch.read_text(log):
                break
            time.sleep(0.05)
        assert "hello" in switch.read_text(log)                      # output went to the file
        assert switch.process_alive(pid, "sleep")
        assert not switch.process_alive(pid, "some-other-program")   # a reused pid would not match
        assert switch.stop_process(pid, "sleep") == "stopped"
        assert not switch.process_alive(pid, "sleep")
        assert switch.stop_process(pid, "sleep") == "already gone"
    finally:
        try:
            os.kill(pid, 9)
        except OSError:
            pass


def test_stop_process_kills_what_ignores_sigterm(tmp_path):
    code = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
    pid = switch.spawn_process([sys.executable, "-c", code], str(tmp_path / "q.log"))
    time.sleep(0.5)                                                  # let python install the handler
    assert switch.stop_process(pid, "SIG_IGN", wait=0.5).startswith("did not stop")
    assert not switch.process_alive(pid, "SIG_IGN")


# ---- openvpn ----

def test_openvpn_conf_server_and_client():
    srv = switch.openvpn_conf("server", "/p").splitlines()
    cli = switch.openvpn_conf("client", "/p").splitlines()
    for common in ("proto udp", "tun-mtu 1400", "data-ciphers AES-256-GCM", "cipher AES-256-GCM", "mssfix 0",
                   "disable-dco", "dev ovpn0", "dev-type tun", "ca /p/ca.crt"):
        assert common in srv and common in cli
    assert "cert /p/server.crt" in srv and "key /p/server.key" in srv
    assert "cert /p/client.crt" in cli and "key /p/client.key" in cli
    assert "server 10.10.0.0 255.255.255.0" in srv and "topology subnet" in srv      # serverA gets .1
    assert "local 10.0.3.2" in srv and "remote-cert-tls client" in srv
    assert "remote 10.0.3.2 1194" in cli and "remote-cert-tls server" in cli and "client" in cli
    assert not any(l.startswith(("secret", "tls-auth", "comp-lzo", "compress")) for l in srv + cli)


class OvpnEnv(VpnEnv):
    """Like VpnEnv, but openssl, rm and rmdir really run (in a temp folder)."""
    def __init__(self, tmp_path, monkeypatch, **kw):
        monkeypatch.setattr(switch, "PKI_DIR", str(tmp_path / "pki"))
        super().__init__(tmp_path, monkeypatch, **kw)
        self.pki = tmp_path / "pki"

    openssl_missing = False

    def runner(self, argv, input=None):
        if argv[0] == "openssl" and self.openssl_missing:
            return 127, "openssl: command not found"
        if argv[0] in ("openssl", "rm", "rmdir"):
            self.calls.append(argv)
            return switch.run_cmd(argv)
        return super().runner(argv, input)

    def spawn(self, argv, log, cwd):
        pid = 100 + len(self.spawned)
        self.spawned.append((pid, argv, cwd))
        os.makedirs(os.path.dirname(log), exist_ok=True)
        if "client.conf" in argv[-1]:
            self.client_started = not self.client_dies
            open(log, "w").write("TLS Error: handshake failed\n" if self.client_dies
                                 else "Initialization Sequence Completed\n")
        else:
            open(log, "w").write("Initialization Sequence Completed\n")
        return pid


needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")


@needs_openssl
def test_openvpn_starts_with_real_certificates(tmp_path, monkeypatch):
    env = OvpnEnv(tmp_path, monkeypatch)
    assert env.sw.switch_to("openvpn") == 0
    (spid, sargv, _), (cpid, cargv, _) = env.spawned
    assert sargv == ["ip", "netns", "exec", "serverA", "openvpn", "--config", str(env.pki / "server.conf")]
    assert cargv == ["ip", "netns", "exec", "client1", "openvpn", "--config", str(env.pki / "client.conf")]
    # the certificates are real and our CA signed them for the right purpose
    for role in ("server", "client"):
        r = subprocess.run(["openssl", "verify", "-CAfile", str(env.pki / "ca.crt"), "-purpose", f"ssl{role}",
                            str(env.pki / f"{role}.crt")], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
    wrong = subprocess.run(["openssl", "verify", "-CAfile", str(env.pki / "ca.crt"), "-purpose", "sslclient",
                            str(env.pki / "server.crt")], capture_output=True, text=True)
    assert wrong.returncode != 0                                    # a server cert is not a client cert
    assert oct((env.pki / "ca.key").stat().st_mode & 0o777) == "0o600"
    assert oct(env.pki.stat().st_mode & 0o777) == "0o700"
    data = switch.State(str(tmp_path)).load()
    assert data["ready"] and data["target"] == "10.10.0.1"
    assert data["interfaces"] == [["serverA", "ovpn0"], ["client1", "ovpn0"]]
    assert [p["match"] for p in data["processes"]] == ["server.conf", "client.conf"]


@needs_openssl
def test_openvpn_off_stops_client_then_server_and_deletes_every_key(tmp_path, monkeypatch):
    env = OvpnEnv(tmp_path, monkeypatch)
    env.sw.switch_to("openvpn")
    assert (env.pki / "ca.key").exists()
    assert env.sw.teardown() == "openvpn"
    assert env.stopped == [101, 100]
    assert not env.pki.exists()                                     # keys, certs, configs and the folder
    assert switch.State(str(tmp_path)).load() is None


@needs_openssl
def test_openvpn_client_failure_cleans_up_everything(tmp_path, monkeypatch):
    env = OvpnEnv(tmp_path, monkeypatch, client_dies=True)
    assert env.sw.switch_to("openvpn") == 1
    assert any("OpenVPN client connects" in l for l in env.out) and any("handshake failed" in l for l in env.out)
    assert 100 in env.stopped and not env.pki.exists()
    assert switch.State(str(tmp_path)).load() is None


def test_openvpn_failing_openssl_stops_and_cleans_up(tmp_path, monkeypatch):
    env = OvpnEnv(tmp_path, monkeypatch)
    env.openssl_missing = True
    assert env.sw.switch_to("openvpn") == 1
    assert any("make the CA" in l for l in env.out) and env.spawned == []
    assert not env.pki.exists()


def test_openvpn_refuses_when_its_interface_is_taken(tmp_path, monkeypatch):
    env = OvpnEnv(tmp_path, monkeypatch, tun_busy=True)
    assert env.sw.switch_to("openvpn") == 1
    assert any("ovpn0 is free in serverA" in l for l in env.out) and env.spawned == []
