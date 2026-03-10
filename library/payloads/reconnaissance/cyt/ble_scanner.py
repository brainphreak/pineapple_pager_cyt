#!/mmc/usr/bin/python3
"""
ble_scanner.py — Passive BLE Advertisement Scanner
Runs hcitool lescan + btmon and parses LE Advertising Reports into SQLite.

Usage:
    ble_scanner.py --db PATH [--hci N] [--daemon] [--pidfile PATH] [--verbose]
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

# ── Apple advertisement type fingerprinting ──────────────────────────
APPLE_ADV_TYPES = {
    0x01: 'AirDrop',
    0x02: 'iBeacon',
    0x03: 'AirPrint',
    0x05: 'AirPlay',
    0x07: 'HomeKit',
    0x08: 'Siri Remote',
    0x09: 'Apple TV',
    0x0A: 'Nearby',
    0x0B: 'Apple Watch',
    0x0C: 'Handoff',
    0x0F: 'Nearby Action',
    0x10: 'Find My',
    0x12: 'Continuity',
    0x1E: 'AirPods',
}

running = True
scan_proc = None
btmon_proc = None


def sig_handler(sig, frame):
    global running
    running = False
    if scan_proc:
        try: scan_proc.terminate()
        except Exception: pass
    if btmon_proc:
        try: btmon_proc.terminate()
        except Exception: pass


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


def parse_apple_type(hex_data: str) -> str:
    """Given raw Company hex data, identify Apple advertisement type."""
    if len(hex_data) >= 2:
        try:
            atype = int(hex_data[:2], 16)
            return APPLE_ADV_TYPES.get(atype, 'Apple Device')
        except ValueError:
            pass
    return 'Apple Device'


def detect_hci() -> int:
    """Return the ID of the first available HCI adapter, or 0 as fallback."""
    try:
        out = subprocess.check_output(['hciconfig'], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            m = re.match(r'hci(\d+):', line)
            if m:
                return int(m.group(1))
    except Exception:
        pass
    return 0


def reset_adapter(hci_id: int) -> bool:
    """Hard-reset the HCI adapter to clear any stuck scan state."""
    os.system(f'hciconfig hci{hci_id} down 2>/dev/null')
    time.sleep(0.5)
    os.system(f'hciconfig hci{hci_id} up 2>/dev/null')
    time.sleep(0.5)
    return True


def scan_once(conn, hci_id: int, verbose: bool) -> bool:
    """Run one scan session. Returns True if it ran for a meaningful time,
    False if it failed to start (adapter error)."""
    global scan_proc, btmon_proc

    # Start passive lescan
    scan_proc = subprocess.Popen(
        ['hcitool', '-i', f'hci{hci_id}', 'lescan', '--passive', '--duplicates'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(0.5)

    # Check if lescan actually started (it exits immediately on adapter error)
    if scan_proc.poll() is not None:
        scan_proc = None
        return False   # signal caller to reset and retry

    # Start btmon
    btmon_proc = subprocess.Popen(
        ['btmon', '-i', f'hci{hci_id}'],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1
    )

    addr = rssi = company = name = addrtype = None
    pending_company_data = False
    batch = []
    BATCH_SIZE = 5
    lines_read = 0

    def flush_batch():
        dbmod.insert_sightings_batch(conn, batch)
        batch.clear()

    while running:
        try:
            line = btmon_proc.stdout.readline()
        except (IOError, ValueError):
            break
        if not line:
            break
        lines_read += 1
        line = line.strip()

        # Start of a new advertising report → reset state
        if 'LE Advertising Report' in line:
            addr = rssi = company = name = addrtype = None
            pending_company_data = False
            continue

        if line.startswith('Address:'):
            m = re.search(r'Address: ([0-9A-Fa-f:]{17})', line)
            if m:
                addr = m.group(1).upper()
            addrtype = 'random' if 'Random' in line else 'public'
            pending_company_data = False

        elif line.startswith('Company:'):
            m = re.search(r'Company: (.+?) \((\d+)\)', line)
            if m:
                company = m.group(1).strip()
                cid = int(m.group(2))
                pending_company_data = (cid == 76)  # Apple = 76
            else:
                company = line.replace('Company:', '').strip()
                pending_company_data = False

        elif line.startswith('Type:') and pending_company_data:
            # btmon prints "Type: Unknown (N)" — N is the Apple adv type ID
            m = re.search(r'Unknown \((\d+)\)', line)
            if m:
                atype = int(m.group(1))
                subtype = APPLE_ADV_TYPES.get(atype, 'Apple Device')
                company = f'Apple/{subtype}'
                pending_company_data = False

        elif 'Name (' in line and ('complete' in line.lower() or 'short' in line.lower()):
            m = re.search(r'Name \([^)]+\): (.+)', line)
            if m:
                name = m.group(1).strip()

        elif line.startswith('RSSI:'):
            m = re.search(r'RSSI: (-?\d+)', line)
            if m and addr:
                rssi = int(m.group(1))
                glat, glon = gpsmod.get_location()
                sighting = dict(
                    mac=addr,
                    source='ble',
                    rssi=rssi,
                    name=name or '',
                    manufacturer=company or '',
                    adv_flags=addrtype or '',
                    ssid_probes='',
                    lat=glat,
                    lon=glon,
                    timestamp=int(time.time())
                )
                batch.append(sighting)
                if verbose:
                    print(f'[ble] {addr:17s} {rssi:4d}dBm  {company or "?":28s}  {name or ""}',
                          flush=True)
                if len(batch) >= BATCH_SIZE:
                    flush_batch()
                addr = rssi = company = name = addrtype = None
                pending_company_data = False

    flush_batch()

    if scan_proc:
        try:
            scan_proc.terminate()
        except Exception:
            pass
        scan_proc = None
    if btmon_proc:
        try:
            btmon_proc.terminate()
        except Exception:
            pass
        btmon_proc = None

    return lines_read > 5   # True = ran properly, False = stalled immediately


def scan_loop(conn, hci_id: int, verbose: bool):
    """Outer loop: reset adapter and retry scan_once on failure."""
    global running
    while running:
        ok = scan_once(conn, hci_id, verbose)
        if not running:
            break
        if not ok:
            # scan failed to start — reset adapter and retry
            reset_adapter(hci_id)
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description='CYT BLE Scanner')
    parser.add_argument('--db',      required=True, help='SQLite database path')
    parser.add_argument('--hci',     type=int, default=-1, help='HCI device number (-1 = auto-detect)')
    parser.add_argument('--daemon',  action='store_true', help='Fork to background')
    parser.add_argument('--pidfile', help='Write PID to file')
    parser.add_argument('--verbose', action='store_true', help='Print sightings to stdout')
    args = parser.parse_args()

    conn = dbmod.open_db(args.db)

    hci_id = args.hci if args.hci >= 0 else detect_hci()

    if args.daemon:
        daemonize()

    if args.pidfile:
        write_pidfile(args.pidfile)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT,  sig_handler)
    signal.signal(signal.SIGHUP,  sig_handler)

    gpsmod.start()   # connect to gpsd in background thread

    # Reset adapter to clear any stuck scan state
    reset_adapter(hci_id)

    if not args.daemon:
        print(f'[ble] Scanning on hci{hci_id} → {args.db}', flush=True)

    try:
        scan_loop(conn, hci_id, args.verbose)
    finally:
        conn.close()
        if args.pidfile and os.path.exists(args.pidfile):
            os.unlink(args.pidfile)


if __name__ == '__main__':
    main()
