# cn-mini-vpn
## Repeating the experiments

Everything below runs on one Ubuntu VM. The commands that build the lab, change the network or capture packets
need `sudo`. Only the steps marked "tested" were run by us (Ubuntu 26.04.1, kernel 7.0.0-43, Python 3.14.4).

### 1. What you need
- Tools: `iperf3`, `wireguard-tools`, `openvpn`, `tshark` (and `ping`, `ip`, `tc` from the base system).
  Optional, to look at captures in a window: `wireshark`. We installed it with `sudo apt install wireshark` and
  answered No to "allow non-superusers to capture packets" (not needed: `capture.py` does the recording).
  Versions we used: iperf3 3.20, wireguard-tools 1.0.20250521, OpenVPN 2.7.0.
- Python 3 libraries from apt: `python3-cryptography`, `python3-flask`, `python3-pytest`. No virtual environment.
- The apt package names above were checked by us with `apt-cache policy`. **We did not test an install on a fresh machine.**
- The Mini VPN needs its keys and a user once (`certs/`, `users.json`, both ignored by git). If
  `switch.py minivpn` says files are missing, follow NOTES.md Sections 3 and 4 (`tools/ca.py init`,
  `tools/ca.py issue vpn-server`, `tools/users.py add alice`; the test user is alice, password pw1).

### 2. Build the lab and check it (tested)
    sudo ./lab/setup.sh              # 7 namespaces, 2 bridges, routes; removes an old lab first
    sudo ./lab/test.sh               # pings work, traceroute shows 10.0.1.1, 10.0.2.2, 10.0.3.2
    python3 -m pytest tests -q       # no sudo; 176 passed when we ran it

### 3. The measurements (tested)
    sudo python3 lab/run_experiments.py --quick     # pipeline check only, not for the report (we did not time it)
    sudo python3 lab/run_experiments.py             # the real run: 5 modes x 4 conditions x 3 runs = 60 runs
It took **34 min 19 s** on our VM, so start it and leave the VM alone. It prints one line per run with the time
left. Each run is an iperf3 TCP test (10 s) and 100 pings (0.2 s apart) to the address `switch.py status` reports,
after a short warm-up ping. Conditions: `none` (no netem), `good`, `normal`, `bad` (presets in `lab/netem.sh`).
Files written to `results/`: `summary.csv` (what the dashboard reads), `rtt_detail.csv`, `table.md` (mean and
sample SD, n-1), `notes.txt` (retries, zero-throughput or slow runs; "clean" if none), `environment.txt`, `run.log`,
and `raw/` (every iperf3 JSON and ping output). At the end it switches the mode and netem off.
Options:
- `--modes`, `--conditions`, `--runs N`: measure only part of the matrix.
- `--iperf-seconds N`: length of each iperf3 test (default 10).
- `--quick`: 1 run, 3 s iperf3, 10 pings, written to `results/quick/`. **This only checks that the pipeline
  works.** 3 s is too short under Bad (in our first quick run WireGuard delivered nothing). Never use quick numbers
  in the report.
- A test that connects but receives nothing is recorded as 0 Mbit/s and listed in `notes.txt`. If iperf3 cannot
  connect it is retried once; a second failure stops the run. If the VM freezes during a run, the script says
  so instead of blaming the VPN (this happened to us once; we repeated the run).
- If a run stops half way, `results/summary.partial.csv` holds what was measured. Re-run; the old files are replaced.

### 4. Packet captures (tested)
    sudo python3 lab/capture.py plain        # also: gre  wireguard  minivpn  openvpn
Records on router1's link to router2 (where netem sits) and writes two files per mode into `captures/`, owned by
you: `MODE.pcapng` and `MODE.summary.txt` (tshark summary plus a list of checks, each `[ok]` or `[MISSING]`).
The mode is brought up while tshark is already recording, so the handshake is in the file. Exit code 0 means all
checks are ok. Plain, GRE, WireGuard and OpenVPN record 2.5 to 5 s of pings plus setup; Mini VPN records 22 s of pings with
a rekey every 8 s instead of 120 s (only for the capture). All four we ran after plain took about 2.5 minutes together. What to look at in each file is in NOTES.md ("What to annotate").
Our five captures are in `captures/`.

**Reading captures (AppArmor).** On Ubuntu 26.04 the `tshark` program is confined by AppArmor. It may only write
and read pcap files under `/tmp`, even as root, so it cannot open a file in the project folder (error:
"You don't have permission to read the file"). That is why `capture.py` records into a private folder in `/tmp`
and copies the file to `captures/` afterwards. To read a capture in the terminal, give tshark a copy in `/tmp`:
    cp captures/minivpn.pcapng /tmp/ && tshark -r /tmp/minivpn.pcapng | head
The Wireshark window (`wireshark` package) was tested and opens files from `captures/` directly; only the
terminal `tshark` has this limit.

### 5. The dashboard Results tab
    python3 dashboard/app.py         # then open http://127.0.0.1:5000 and choose the Results tab
It reads `results/summary.csv` (columns protocol, condition, run, throughput_mbps, rtt_ms, loss_pct) and shows
mean and sample SD per protocol and condition. Checked: through the dashboard's API the numbers for all 15 cells
matched our own calculation from `summary.csv`. **Not checked: the page in a real browser.** To preview the tab
without measurements, use the fake file: `python3 dashboard/app.py --results-file tests/fake_summary.csv`
(fake numbers, not measurements).

### 6. Clean up
    sudo python3 lab/switch.py off ; sudo ./lab/netem.sh off ; sudo ./lab/teardown.sh
