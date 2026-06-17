# BeaconButty demo

A standalone Flask demo of the [BeaconButty](https://github.com/mustard-research/BeaconButty) network beacon detector. Runs on any Raspberry Pi (or laptop) with just Python + Flask — **no Zeek, RITA, ClickHouse, Suricata, or live packet capture required**.

Intended for conference talks, training sessions, and "show me what it looks like before I commit to building one." Every form submission, alert toggle, backup button, and FP add returns success but **changes nothing**. A "DEMO MODE" banner across the top of every page makes that clear.

The production system runs on a Raspberry Pi 5 in-line as the NAT router with Zeek 8 + RITA v5.1.1 + ClickHouse + Suricata. This demo replaces all of that with pre-baked Python dicts.

---

## Hardware

Any Pi from a Pi Zero 2 W upwards. 512 MB RAM is plenty (the whole demo fits in ~30 MB resident). Raspberry Pi OS Lite (32- or 64-bit) Bookworm or Trixie.

Also runs fine on a laptop for local development — see [Run without installing](#run-without-installing) below.

---

## Quick install — fresh Pi, one command

After flashing **Raspberry Pi OS Lite** to your Pi's storage with Pi Imager (set hostname, your username, your SSH key in the OS-customisation step), boot the Pi, SSH in, then:

```sh
curl -sSL https://raw.githubusercontent.com/mustard-research/beaconbutty-demo/master/bootstrap.sh | sudo bash
```

That's it. The script installs `python3-flask` + `git`, clones this repo into `/opt/beaconbutty-demo/`, installs a systemd unit, and starts the service.

Browse to **http://`<pi-ip>`:5000/** — the IP is printed at the end of the script (`hostname -I` works too).

To watch logs:

```sh
sudo journalctl -u beaconbutty-demo -f
```

To stop / restart:

```sh
sudo systemctl stop beaconbutty-demo
sudo systemctl restart beaconbutty-demo
```

---

## Manual install (existing clone)

If you've already cloned the repo (or want to inspect everything before running it):

```sh
sudo apt update
sudo apt install -y python3-flask git
git clone https://github.com/mustard-research/beaconbutty-demo
cd beaconbutty-demo
sudo bash install.sh
```

---

## Run without installing

On your laptop (or anywhere you don't want a systemd service):

```sh
git clone https://github.com/mustard-research/beaconbutty-demo
cd beaconbutty-demo
pip3 install flask         # or use your system's python3-flask package
python3 app.py
```

Browse to **http://localhost:5000/**. Override the port with `PORT=8080 python3 app.py`.

---

## What's demonstrated

| Page | Shows |
|------|-------|
| **Dashboard** (`/`) | System tiles (temp/CPU/mem/disk/log2ram/fans), beacon count, Suricata alert summary, alert digest |
| **System** (`/system`) | 24-hour CPU temperature, CPU load, and fan-state chart |
| **Bandwidth** (`/bandwidth`) | Top-talker time-series + per-device drill-down (RITA ClickHouse-style) |
| **Beacons** (`/beacons`) | Device Hotlist with severity counts, top high-score beacons, FP workflow, JA4 enrichment |
| **Slow Beacons** (`/beacons/slow`) | Multi-day low-rate beacon candidates (the detector that catches sleep-cycle implants RITA's daily window misses) |
| **Suricata** (`/suricata`) | IDS signature rollup, LAN-device breakdown, threat-category panels |
| **Rules** (`/suricata/rules`) | Local-rule management + Emerging Threats ruleset stats |
| **Network Intel** (`/network`) | JA4 threats, L2/ARP anomalies, TLS / DNS anomalies, exfil candidates, night activity |
| **Assets** (`/assets`) | LAN inventory with MAC vendor, JA4 threat badges, "ghost" entries for devices seen in the last 14 days |
| **False Positives** (`/fps`) | Device-, domain-, and protocol-keyed FP registry |
| **Health** (`/health`) | Structured health-check cards, alert-toggle table, cert info, **Teams Relay Detector** card (DragonForce / Backdoor.Turn signal — see the [public detector doc](https://github.com/mustard-research/BeaconButty/blob/master/docs/investigation/teams-relay-detection.md)) |
| **Backup** (`/backup`) | Config snapshots, full archives, USB clone interface |

The fixtures include a few headline findings so the demo tells a story when you click around: a high-severity Sliver Agent JA4 hit, a Teams-relay anomaly (`new-JA4 + long-flow`), a slow-cadence beacon with very low interval CV, an Awair air-quality monitor and a Peloton in the FP registry.

---

## Customising the demo

All fixture data lives in **`demo_data.py`**. Edit the relevant section and restart:

```sh
sudo systemctl restart beaconbutty-demo
# or, if running locally:  Ctrl-C, then python3 app.py again
```

| Edit this | To change |
|-----------|-----------|
| `DASHBOARD` | Front-page tiles (CPU/mem/disk/fans/uptime) and counts |
| `BEACONS['beacon_data']` | Device Hotlist rows, top high-score beacons, investigate list |
| `SLOW_PAYLOAD` | Slow-cadence candidates and their grouping |
| `NETWORK_INTEL` | Every panel on the Network Intel page |
| `ASSETS` | LAN inventory, JA4 summaries, ghost entries |
| `SURICATA` | Signature list, LAN rows, threat panels |
| `RULES` | Local Suricata rule list + ET ruleset stats |
| `FPS` | Device / domain / protocol FP entries |
| `HEALTH` | Health-check sections, cert info, Teams Relay Detector card |
| `BACKUP` | Backup file list, USB drives, archive log |
| `SYSTEM_TIMESERIES` | `/system` chart points |
| `BANDWIDTH_DATA` | `/bandwidth` chart + top-talkers table |
| `ALERT_CONFIG` | Default-enabled-vs-disabled state per alert type |
| `TEAMS_DETECTOR_CONFIG` / `_REPORT` | Teams Relay Detector card content |

All timestamps in `demo_data.py` derive from a fixed `REF_DT = 2026-06-17 14:30 UTC` so the demo looks deterministic across reloads — change `REF_DT` (and re-pin downstream values if you really want to relocate it in time) to age it forward.

---

## Architecture vs production

|  | Demo | Production |
|---|------|-----------|
| Data source | `demo_data.py` (Python dicts) | Zeek `conn.log`/`ssl.log`/`quic.log`/`arp.log`, RITA daily ClickHouse DBs, Suricata `eve.json`, system files in `/var/lib/beaconbutty/` |
| Live capture | None | `eth1` running Zeek 8 on the LAN gateway |
| Mutations | All stubbed, return success | Actually write `false-positives.conf`, restart Suricata, run rpi-clone, etc. |
| Slack | Stubbed | Real Slack workspace via AWS Lambda (`alert.sh` → API Gateway → DynamoDB dedup → Slack webhook) |
| CPU usage | <5 % on a Pi Zero 2 W | 15–40 % on a Pi 5 (Zeek is the hot path) |
| Persistence | None (one-process Flask) | Daily backups, weekly archives, USB clones |

When the production templates change, the demo templates **must** be re-copied verbatim — see [CLAUDE.md](CLAUDE.md) for the contributor guide.

---

## Troubleshooting

**Service doesn't start**

```sh
sudo journalctl -u beaconbutty-demo -n 50 --no-pager
```

Common causes: `python3-flask` not installed (re-run install), port 5000 already in use (`sudo ss -tlnp 'sport = :5000'`), bad systemd unit file (compare against `systemd/beaconbutty-demo.service`).

**Port 5000 is in use**

Edit `/etc/systemd/system/beaconbutty-demo.service`, change the `Environment=PORT=5000` line, then `sudo systemctl daemon-reload && sudo systemctl restart beaconbutty-demo`.

**"Internal server error" on a page**

Something in `demo_data.py` doesn't supply a field a template needs. Check logs:

```sh
sudo journalctl -u beaconbutty-demo -n 50 --no-pager | grep -A 5 'jinja\|UndefinedError\|KeyError'
```

…then add the missing key to the relevant dict in `demo_data.py` and restart.

**"Demo mode" banner missing**

Make sure `app.config["DEMO_MODE"] = True` is set in `app.py` (it should be — this is the marker the banner block in `base.html` checks).

**Want to remove the demo entirely**

```sh
sudo systemctl disable --now beaconbutty-demo
sudo rm /etc/systemd/system/beaconbutty-demo.service
sudo rm -rf /opt/beaconbutty-demo
sudo systemctl daemon-reload
```

---

## License

MIT (same as production BeaconButty). See [the upstream LICENSE](https://github.com/mustard-research/BeaconButty/blob/master/LICENSE).
