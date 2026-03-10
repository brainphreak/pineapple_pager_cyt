# Chasing Your Tail

**Passive surveillance detection for the Hak5 WiFi Pineapple Pager.**

Detects physical surveillance — stalkers, tails, surveillance teams — by passively monitoring the wireless signals emitted by nearby devices. If the same device keeps appearing around you across time and location, you're probably being followed.

---

## How it works

Every phone, laptop, fitness tracker, and vehicle continuously broadcasts wireless signals that contain unique identifiers. These signals are invisible to the people carrying the devices, but they're trivially capturable with the right hardware.

Chasing Your Tail does three things:

1. **Captures** BLE advertisements, WiFi probe requests, and drone beacons passively — no transmission, entirely silent
2. **Scores** each device based on how suspicious its pattern of appearances is
3. **Alerts** you when a device crosses a threat threshold

### The threat score

Each device receives a score between 0.0 and 1.0 computed every 30 seconds:

| Factor | What it measures | Max contribution |
|--------|-----------------|-----------------|
| Duration | Device present >5/10/15/20 minutes | +0.60 |
| Frequency | Sighting rate above 0.5/min | +0.10 |
| Multi-location | Seen at >1 or >2 distinct GPS coordinates (~100m cells) | +0.30 |
| Proximity | RSSI stronger than -60/-50/-40 dBm | +0.20 |

Scores map to threat levels:

| Score | Level | Meaning |
|-------|-------|---------|
| < 0.20 | NORMAL | Incidental — background noise |
| 0.20 – 0.39 | LOW | Early signal — device is persistent |
| 0.40 – 0.59 | MEDIUM | Likely following — has been near you >10 min |
| 0.60 – 0.79 | HIGH | Strong indicator — multiple locations or long duration |
| ≥ 0.80 | CRITICAL | Almost certain surveillance |

### What it captures

**BLE (Bluetooth Low Energy)**
Passive scan on `hci1` using `hcitool lescan` + `btmon`. Captures every advertising device in range (~10–50m depending on conditions). Identifies Apple device subtypes (AirDrop, Find My, AirPods, Nearby, etc.) from manufacturer advertisement payloads.

**WiFi probe requests**
Monitor mode capture on `wlan0mon` using `tcpdump`. When a phone's WiFi is on, it constantly broadcasts the names of remembered networks it's looking for. These probe requests contain the device's MAC address and the SSID names.

**Drone beacons**
802.11 beacon frames from DJI, Parrot, and other commercial drones. Drones broadcast their identity continuously — the scanner matches against 13 DJI OUIs plus SSID name patterns (MAVIC-, PHANTOM-, SPARK-, MINI-, etc.).

### MAC rotation detection (SSID clustering)

Modern phones rotate their MAC address periodically to defeat tracking. CYT counters this:

A phone probing for "HomeNetwork" AND "WorkWiFi" from MAC `AA:BB:CC:DD:EE:FF` — then later probing for the same two networks from a different MAC `11:22:33:44:55:66` — is almost certainly the same physical device.

Every analyzer cycle, CYT groups MACs that share 2 or more probed SSIDs into a **cluster**. The cluster is scored as a unit using the combined sighting history of all its member MACs, with a +0.15 cluster boost applied to the final score.

### Cross-protocol co-occurrence grouping

Surveillance typically involves multiple devices on the same person — e.g., a phone (WiFi) and earbuds (BLE) always moving together.

CYT identifies **co-occurrence groups**: BLE and WiFi devices that consistently appear in the same 60-second time windows across at least 5 time buckets with ≥65% co-presence rate. Members of a group share the highest threat score in the group, with a +0.10 boost. Groups are shown as `G1`, `G2`, etc. badges.

### GPS and location tracking

A USB GPS dongle provides coordinates. Each sighting is stamped with lat/lon. The multi-location score factor only fires when a device is seen at two or more distinct coordinates (~100m resolution) — meaning it has followed you to a different physical location, not just been in range at the same spot.

Without a GPS fix (indoors, no satellite), the location factor simply does not score. All other scoring factors remain active.

---

## Hardware

- **Platform**: Hak5 WiFi Pineapple Pager (MIPS MT7628AN, OpenWrt 24.10)
- **BLE**: MT7921U on `hci1` — passive scan, BT 5.2, 2M PHY
- **WiFi**: MT7921U on `wlan0mon` — 802.11 monitor mode
- **GPS**: USB GPS dongle on `/dev/ttyACM0`, connected via `gpsd`
- **Display**: 480×222 RGB565 framebuffer, controlled via `pagerctl`

### Dependencies

- `python3` + `python3-ctypes` — installed via opkg (payload prompts to install if missing)
- `pagerctl` — hardware control library (`libpagerctl.so` + `pagerctl.py`), auto-copied from PAGERCTL payload or `payload/lib/`

---

## Payload structure

```
payload/
  payload.sh        Entry point — dependency checks, UI launch, headless mode
  ble_scanner.py    Passive BLE advertisement scanner daemon
  wifi_scanner.py   WiFi probe request + drone beacon capture daemon
  analyzer.py       Threat scoring engine, clustering, co-occurrence grouping
  cyt_app.py        On-device pagerctl GUI (startup menu, device list, detail view)
  cyt_ui.py         Low-level display drawing primitives
  web_server.py     Live dashboard web server on port 8080
  reporter.py       Generate MD + HTML intelligence reports
  db.py             SQLite database layer (shared by all modules)
  gps.py            Background gpsd reader thread
```

Data files (not committed):

```
  cyt.db            Scan database — sightings, persistence scores, clusters
  whitelist.db      Persistent whitelist — survives cyt.db deletion
```

---

## Usage

### Running the payload

**From the Pineapple Pager menu** — select the payload from the reconnaissance category. The startup menu appears immediately. Choose to start the GUI (launches scanners + display), run headless (scanners only), or exit.

**Via SSH:**

```bash
ssh root@172.16.52.1

# GUI mode (starts scanners + display UI)
/mmc/root/payloads/reconnaissance/cyt/payload.sh

# Headless mode (scanners only, no display — keeps running after SSH disconnect)
/mmc/root/payloads/reconnaissance/cyt/payload.sh --headless

# Check what's running
/mmc/root/payloads/reconnaissance/cyt/payload.sh --status

# Stop everything
/mmc/root/payloads/reconnaissance/cyt/payload.sh --stop
```

### On-device display UI

The display shows a scrollable list of tracked devices sorted by threat score. Each row shows MAC, source (BLE/WiFi/Drone), threat level, RSSI, and any cluster (`C1`) or co-occurrence group (`G1`) badges.

**Device list navigation:**

| Button | Action |
|--------|--------|
| DOWN | Scroll list down |
| UP | Scroll list up |
| LEFT / RIGHT | Cycle source filter (All / BLE / WiFi / Drone) |
| A | Open detail view for selected device |
| B | Open exit menu |

**Detail view:**

| Button | Action |
|--------|--------|
| A or B | Back to device list |
| LEFT | Toggle whitelist (add / remove) |

**Startup menu** also includes a **Manage Whitelist** option to view and remove whitelisted devices.

### Vibration alerts

When a device's threat score crosses a threshold for the first time, the device vibrates:

| Level | Threshold | Pattern |
|-------|-----------|---------|
| Medium | ≥ 0.40 | 1 short pulse |
| High | ≥ 0.60 | 2 medium pulses |
| Critical | ≥ 0.80 | 3 long pulses |

Each device alerts once per level — escalation (High → Critical) triggers an additional alert.

### Web dashboard

While running, a live dashboard is available at:

```
http://172.16.52.1:8080/
```

The dashboard auto-refreshes every 5 seconds. Summary cards show total device count by source, threat level breakdown, cluster count, and co-occurrence group count. The device table is filterable by source and threat level. Whitelisted devices are hidden from the table and shown in a separate panel.

Additional endpoints:

| URL | Returns |
|-----|---------|
| `/api/status` | Live status summary as JSON |
| `/api/devices` | Full device list from database as JSON |
| `/api/whitelist` | Whitelist entries as JSON (GET / POST / DELETE) |
| `/report` | Generated HTML intelligence report (on demand) |

### Whitelist

Known devices (your own phone, companions) can be whitelisted to exclude them from scoring and display.

- **Pager**: A button in detail view — or via Manage Whitelist in the startup menu
- **Web**: Whitelist button per row, with a dedicated whitelist management panel

Whitelist data is stored in `whitelist.db` — a separate file from `cyt.db`. You can delete `cyt.db` to reset scan history without losing your whitelist.

### Generating a report

```bash
# On device
cd /mmc/root/payloads/reconnaissance/cyt/
python3 reporter.py --db cyt.db --out /tmp/cyt_report

# Options
#   --window 7200     analysis window in seconds (default 3600)
#   --min-score 0.40  only include devices above this score
```

Outputs `cyt_report.md` and `cyt_report.html`. The HTML report is dark-themed with color-coded rows, summary cards, and cluster/group columns.

---

## Interpreting results

**Start a route.** The tool needs time to build profiles. Scores are intentionally conservative in the first 5 minutes to avoid false positives.

**MEDIUM after 10+ minutes** — a device has been consistently near you. Could be coincidence (same commute, same coffee shop). Note the manufacturer and device type.

**HIGH** — a device has been near you across multiple GPS locations or for over 15 minutes with strong signal. This warrants attention.

**CRITICAL** — 20+ minutes, strong signal, multiple locations. Treat this seriously.

**Clusters** — a MAC rotation cluster means a device is actively trying to evade tracking tools. Normal users' phones rotate MACs as a privacy feature, but the rotation only matters if the same device keeps following you — the threat score accounts for this.

**Groups** — a co-occurrence group means multiple different devices (e.g., BLE + WiFi) are always moving together. A single person on surveillance is likely carrying both.

**Drone alerts** — any device showing as source `DRONE` is a detected UAV broadcasting DJI or drone-type beacons nearby.

---

## Operational notes

- Run the tool for at least 15–20 minutes to collect meaningful data before interpreting scores
- In dense urban environments (crowded transit, markets), HIGH-score devices may be coincidental — use GPS multi-location scoring as the stronger signal
- Whitelist your own devices immediately on first run to reduce noise
- The database accumulates all sightings; delete `cyt.db` to start a clean baseline — your whitelist in `whitelist.db` is not affected
- Battery life on the Pineapple Pager limits continuous operation — headless mode consumes less power than GUI mode

---

## Based on

The "Chasing Your Tail" counter-surveillance concept by [Hackers Arise](https://hackers-arise.com/physical-surveillance-detection-using-chasing-your-tail-to-know-if-youre-being-followed/) and the [Chasing Your Tail NG project](https://github.com/ArgeliusLabs/Chasing-Your-Tail-NG) by Argelius Labs.

This implementation extends the original WiFi-only concept with full BLE tracking, drone beacon detection, MAC rotation clustering, cross-protocol co-occurrence grouping, GPS stamping, vibration alerts, and a purpose-built interface for the Hak5 WiFi Pineapple Pager.
