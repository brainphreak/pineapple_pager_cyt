#!/mmc/usr/bin/python3
"""
wifi_scanner.py — WiFi Probe Request Capture
Uses tcpdump on monitor interface (wlan0mon already in monitor mode on Pineapple).
Logs source MAC, probed SSID, and RSSI to SQLite.

Usage:
    wifi_scanner.py --db PATH [--iface IFACE] [--daemon] [--pidfile PATH] [--verbose]
"""
import argparse
import os
import re
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db as dbmod
import gps as gpsmod

running = True
tcpdump_proc = None

# MAC OUI manufacturer lookup — loaded from oui.tsv (Wireshark manuf data, ~38k entries)
_OUI_MAP = None

def _load_oui_map():
    global _OUI_MAP
    if _OUI_MAP is not None:
        return _OUI_MAP
    _OUI_MAP = {}
    tsv = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'oui.tsv')
    try:
        with open(tsv) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('	', 1)
                if len(parts) == 2:
                    _OUI_MAP[parts[0]] = parts[1]
    except Exception:
        pass
    return _OUI_MAP


# Drone OUI table — DJI, Parrot, and other commercial UAV makers
DRONE_OUI = {
    '60:60:1f': 'DJI',
    '48:1c:b9': 'DJI',
    '90:3a:e6': 'DJI',
    'd0:54:8b': 'DJI',
    '2c:57:41': 'DJI',
    '0c:ae:7d': 'DJI',
    '08:5b:0e': 'DJI',
    '34:d2:62': 'DJI',
    'a0:14:3d': 'DJI',
    '04:6c:59': 'Parrot',
    '90:03:b7': 'Parrot',
    'a0:14:3d': 'Skydio',
    '00:26:7e': '3DR',
}

# DJI SSIDs follow "MODELNAME-SERIALHEX" convention
DRONE_SSID_PREFIXES = (
    'MAVIC-', 'PHANTOM-', 'SPARK-', 'MINI-', 'AIR2-',
    'FPV-', 'TELLO-', 'MATRICE-', 'AGRAS-', 'DJI-',
)


def drone_check(mac: str, ssid: str) -> str:
    """Return manufacturer string if this beacon looks like a drone, else ''."""
    oui = mac[:8].lower()
    if oui in DRONE_OUI:
        return DRONE_OUI[oui]
    if ssid:
        for prefix in DRONE_SSID_PREFIXES:
            if ssid.upper().startswith(prefix):
                return 'Drone'
    return ''


def sig_handler(sig, frame):
    global running
    running = False


def daemonize():
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    sys.stdin  = open('/dev/null', 'r')
    sys.stdout = open('/dev/null', 'w')
    sys.stderr = open('/dev/null', 'w')


def write_pidfile(path):
    with open(path, 'w') as f:
        f.write(f'{os.getpid()}\n')


def oui_lookup(mac: str) -> str:
    try:
        if int(mac.split(':')[0], 16) & 2:
            return 'Randomized'
    except Exception:
        pass
    prefix = mac[:8].lower()
    return _load_oui_map().get(prefix, '')


def auto_detect_iface() -> str:
    """Return first available monitor interface."""
    for iface in ('wlan0mon', 'wlan1mon', 'wlan2mon'):
        path = f'/sys/class/net/{iface}'
        if os.path.exists(path):
            return iface
    return 'wlan0mon'  # fallback


def scan_once(conn, iface: str, verbose: bool) -> bool:
    """One tcpdump session. Returns True if it ran meaningfully, False on immediate failure."""
    global tcpdump_proc

    tcpdump_proc = subprocess.Popen(
        ['tcpdump', '-i', iface, '-l', '-e',
         '(type mgt subtype probe-req) or (type mgt subtype beacon)'],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1
    )
    time.sleep(0.5)

    # Check if tcpdump started
    if tcpdump_proc.poll() is not None:
        tcpdump_proc = None
        return False

    batch = []
    BATCH_SIZE = 5
    lines_read = 0

    def flush_batch():
        dbmod.insert_sightings_batch(conn, batch)
        batch.clear()

    while running:
        try:
            line = tcpdump_proc.stdout.readline()
        except (IOError, ValueError):
            break
        if not line:
            break
        lines_read += 1
        line = line.strip()

        # Classify frame type first — skip lines that are neither
        is_beacon = 'Beacon (' in line
        is_probe  = 'Probe Request (' in line
        if not is_beacon and not is_probe:
            continue

        mac_m  = re.search(r'SA:([0-9a-f:]{17})', line)
        rssi_m = re.search(r'(-\d+)dBm', line)
        if not mac_m:
            continue

        mac  = mac_m.group(1).upper()
        rssi = int(rssi_m.group(1)) if rssi_m else 0

        if is_beacon:
            ssid_m = re.search(r'Beacon \(([^)]*)\)', line)
            ssid   = ssid_m.group(1).strip() if ssid_m else ''
            mfr    = drone_check(mac, ssid)
            if not mfr:
                continue          # skip ordinary AP beacons
            source      = 'drone'
            adv_flags   = 'beacon'
            ssid_probes = ''
        else:  # probe request
            ssid_m = re.search(r'Probe Request \(([^)]*)\)', line)
            ssid   = ssid_m.group(1).strip() if ssid_m else ''
            source      = 'wifi'
            mfr         = oui_lookup(mac)
            adv_flags   = 'probe'
            ssid_probes = ssid

        glat, glon = gpsmod.get_location()
        sighting = dict(
            mac=mac,
            source=source,
            rssi=rssi,
            name=ssid,
            manufacturer=mfr,
            adv_flags=adv_flags,
            ssid_probes=ssid_probes,
            lat=glat,
            lon=glon,
            timestamp=int(time.time())
        )
        batch.append(sighting)

        if verbose:
            tag = '[drone]' if source == 'drone' else '[wifi] '
            print(f'{tag} {mac:17s} {rssi:4d}dBm  SSID:"{ssid}"  {mfr}', flush=True)

        if len(batch) >= BATCH_SIZE:
            flush_batch()

    flush_batch()

    if tcpdump_proc:
        try:
            tcpdump_proc.terminate()
        except Exception:
            pass
        tcpdump_proc = None

    return lines_read > 0


def scan_loop(conn, iface: str, verbose: bool):
    """Outer loop: retry scan_once on failure."""
    global running
    while running:
        ok = scan_once(conn, iface, verbose)
        if not running:
            break
        if not ok:
            time.sleep(2)  # brief pause before retry


def main():
    parser = argparse.ArgumentParser(description='CYT WiFi Scanner')
    parser.add_argument('--db',      required=True, help='SQLite database path')
    parser.add_argument('--iface',   help='Monitor interface (auto-detect if omitted)')
    parser.add_argument('--daemon',  action='store_true', help='Fork to background')
    parser.add_argument('--pidfile', help='Write PID to file')
    parser.add_argument('--verbose', action='store_true', help='Print sightings to stdout')
    args = parser.parse_args()

    iface = args.iface or auto_detect_iface()

    conn = dbmod.open_db(args.db)

    if args.daemon:
        daemonize()

    if args.pidfile:
        write_pidfile(args.pidfile)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT,  sig_handler)

    gpsmod.start()   # connect to gpsd in background thread

    if not args.daemon:
        print(f'[wifi] Capturing on {iface} → {args.db}', flush=True)

    try:
        scan_loop(conn, iface, args.verbose)
    finally:
        conn.close()
        if args.pidfile and os.path.exists(args.pidfile):
            os.unlink(args.pidfile)


if __name__ == '__main__':
    main()
