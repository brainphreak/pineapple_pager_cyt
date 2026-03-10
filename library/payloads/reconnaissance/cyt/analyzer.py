#!/mmc/usr/bin/python3
"""
analyzer.py — Threat Scoring Engine for Chasing Your Tail
Reads sightings from SQLite, computes persistence scores, writes alerts.log
and status.json.  Runs every --interval seconds as a daemon.

Usage:
    analyzer.py --db PATH [--log PATH] [--status PATH]
                [--interval N] [--window N] [--daemon] [--pidfile PATH]
                [--once] [--verbose]
"""
import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db as dbmod

running = True
do_analysis = False

# Threat level thresholds
T_NORMAL   = 0.20
T_LOW      = 0.40
T_MEDIUM   = 0.60
T_HIGH     = 0.80

ALERT_COOLDOWN = 300   # seconds between repeat alerts for same MAC
CLUSTER_BOOST  = 0.15  # extra score for devices detected using MAC rotation
GROUP_BOOST    = 0.10  # extra score for devices in a co-occurrence group


def build_ssid_clusters(conn, since: int) -> dict:
    """Group WiFi MACs sharing ≥2 probed SSIDs — likely the same physical device
    rotating its MAC address.  Returns {mac: cluster_id} for clustered MACs only."""
    rows = conn.execute("""
        SELECT mac, GROUP_CONCAT(DISTINCT ssid_probes) AS ssids
        FROM sightings
        WHERE source = 'wifi'
          AND ssid_probes IS NOT NULL AND ssid_probes != ''
          AND timestamp >= ?
        GROUP BY mac
    """, (since,)).fetchall()

    # Build mac → frozenset of SSIDs (need ≥1 SSID to be useful)
    mac_ssids: dict = {}
    for r in rows:
        ssids = frozenset(s.strip() for s in (r['ssids'] or '').split(',') if s.strip())
        if ssids:
            mac_ssids[r['mac']] = ssids

    if not mac_ssids:
        return {}

    # Union-Find
    parent = {m: m for m in mac_ssids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        pa, pb = find(a), find(b)
        if pa != pb:
            parent[pb] = pa

    macs = list(mac_ssids)
    for i in range(len(macs)):
        for j in range(i + 1, len(macs)):
            if len(mac_ssids[macs[i]] & mac_ssids[macs[j]]) >= 2:
                union(macs[i], macs[j])

    # Assign integer IDs only to non-singleton groups
    root_id: dict = {}
    next_id = 1
    result: dict = {}
    for m in macs:
        root = find(m)
        if root not in root_id:
            members = [x for x in macs if find(x) == root]
            if len(members) >= 2:
                root_id[root] = next_id
                next_id += 1
        if root in root_id:
            result[m] = root_id[root]
    return result


def build_cooccurrence_groups(conn, since: int,
                               bucket_sec: int = 60,
                               min_buckets: int = 5,
                               min_ratio: float = 0.65) -> dict:
    """Group devices that consistently appear in the same time windows.
    Catches cross-protocol co-occurrence: e.g. a phone's WiFi probe + Apple Watch BLE
    always appearing together means they're on the same person.
    Returns {mac: group_id} for grouped devices only."""

    rows = conn.execute(
        "SELECT mac, timestamp FROM sightings WHERE timestamp >= ?", (since,)
    ).fetchall()

    # Build {mac: set of minute-buckets it was seen in}
    mac_buckets: dict = {}
    for r in rows:
        b = r[0], r[1] // bucket_sec
        if r[0] not in mac_buckets:
            mac_buckets[r[0]] = set()
        mac_buckets[r[0]].add(r[1] // bucket_sec)

    # Only consider devices with enough presence to be meaningful
    macs = [m for m, b in mac_buckets.items() if len(b) >= min_buckets]
    if len(macs) < 2:
        return {}

    # Union-Find
    parent = {m: m for m in macs}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        pa, pb = find(a), find(b)
        if pa != pb:
            parent[pa] = pb

    # Link pairs whose time-window overlap ratio exceeds the threshold
    for i in range(len(macs)):
        for j in range(i + 1, len(macs)):
            a, b = macs[i], macs[j]
            shared = len(mac_buckets[a] & mac_buckets[b])
            if shared == 0:
                continue
            ratio = shared / min(len(mac_buckets[a]), len(mac_buckets[b]))
            if ratio >= min_ratio:
                union(a, b)

    # Assign IDs to non-singleton groups
    root_id: dict = {}
    next_id = 1
    result:  dict = {}
    for m in macs:
        root = find(m)
        if root not in root_id:
            members = [x for x in macs if find(x) == root]
            if len(members) >= 2:
                root_id[root] = next_id
                next_id += 1
        if root in root_id:
            result[m] = root_id[root]

    return result


def sig_handler(sig, frame):
    global running, do_analysis
    if sig in (signal.SIGTERM, signal.SIGINT):
        running = False
    elif sig in (signal.SIGUSR1, signal.SIGHUP):
        do_analysis = True


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


def threat_level(score: float) -> str:
    if score >= T_HIGH:   return 'CRITICAL'
    if score >= T_MEDIUM: return 'HIGH'
    if score >= T_LOW:    return 'MEDIUM'
    if score >= T_NORMAL: return 'LOW'
    return 'NORMAL'


def compute_score(row: dict) -> float:
    """Compute threat score 0.0–1.0 from aggregated sighting data."""
    now = int(time.time())
    last_seen = row['last_seen'] or now
    first_seen = row['first_seen'] or now

    # If gone for > 10 minutes, not a current threat
    since_last = now - last_seen
    if since_last > 600:
        return 0.0

    duration_min = (last_seen - first_seen) / 60.0
    count = row['sighting_count'] or 0
    avg_rssi = row['avg_rssi'] or -100
    locs = row['locations_seen'] or 0

    score = 0.0

    # Duration: how long has this device been nearby?  (max 0.60)
    if duration_min >  5: score += 0.15
    if duration_min > 10: score += 0.15
    if duration_min > 15: score += 0.15
    if duration_min > 20: score += 0.15

    # Frequency: sightings per minute                  (max 0.10)
    denom = max(duration_min, 1.0)
    if count / denom > 0.5:
        score += 0.10

    # Multi-location (GPS required)                    (max 0.30)
    if locs > 1: score += 0.20
    if locs > 2: score += 0.10

    # Proximity / signal strength                      (max 0.20)
    if avg_rssi > -60: score += 0.10
    if avg_rssi > -50: score += 0.05
    if avg_rssi > -40: score += 0.05

    return min(score, 1.0)


class AlertTracker:
    """Prevent spamming repeat alerts for the same MAC."""
    def __init__(self):
        self._last: dict[str, tuple[float, int]] = {}  # mac → (score, time)

    def should_alert(self, mac: str, score: float, threshold: float) -> bool:
        if score < threshold:
            return False
        now = int(time.time())
        prev_score, prev_time = self._last.get(mac, (0.0, 0))
        delta = score - prev_score
        age   = now - prev_time
        if delta >= 0.15 or age >= ALERT_COOLDOWN:
            self._last[mac] = (score, now)
            return True
        return False


def write_alert(logf, row: dict) -> None:
    ts = datetime.fromtimestamp(row['last_seen'] or time.time()).strftime('%Y-%m-%d %H:%M:%S')
    dur = int((row['last_seen'] - row['first_seen']) / 60) if row['first_seen'] else 0
    mfr = row.get('manufacturer') or 'Unknown'
    nm  = row.get('name') or ''
    line = (
        f"[{ts}] {threat_level(row['threat_score']):<8}  {row['source']:<4}  "
        f"{row['mac']}  {mfr:<30s}  {nm:<20s}  "
        f"score={row['threat_score']:.2f}  rssi={row['avg_rssi']}  "
        f"seen={row['sighting_count']}  dur={dur}m\n"
    )
    logf.write(line)
    logf.flush()


def write_status_json(path: str, devices: list,
                       ble_total: int, wifi_total: int,
                       drone_total: int = 0, n_clusters: int = 0,
                       n_groups: int = 0, window_sec: int = 3600) -> None:
    tmp = path + '.tmp'
    data = {
        'updated':        int(time.time()),
        'window_sec':     window_sec,
        'total_tracked':  len(devices),
        'ble_devices':    ble_total,
        'wifi_devices':   wifi_total,
        'drone_devices':  drone_total,
        'clustered_macs': n_clusters * 2,
        'grouped_devices': n_groups,
        'critical':  sum(1 for d in devices if d['threat_score'] >= 0.80),
        'high':      sum(1 for d in devices if 0.60 <= d['threat_score'] < 0.80),
        'medium':    sum(1 for d in devices if 0.40 <= d['threat_score'] < 0.60),
        'low':       sum(1 for d in devices if 0.20 <= d['threat_score'] < 0.40),
        'devices': [
            {
                'mac':          d['mac'],
                'source':       d['source'],
                'score':        round(d['threat_score'], 3),
                'level':        threat_level(d['threat_score']),
                'rssi':         d['avg_rssi'],
                'seen':         d['sighting_count'],
                'duration':     int((d['last_seen'] - d['first_seen'])) if d['first_seen'] else 0,
                'name':         d.get('name') or '',
                'manufacturer': d.get('manufacturer') or '',
                'first_seen':   d['first_seen'],
                'last_seen':    d['last_seen'],
                'cluster_id':   d.get('cluster_id'),
                'group_id':     d.get('group_id'),
            }
            for d in devices
        ]
    }
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def run_analysis(conn, logf, status_path: str,
                  window_sec: int, alert_tracker: AlertTracker,
                  verbose: bool, wl_conn=None) -> list:
    since = int(time.time()) - window_sec
    rows  = dbmod.aggregate_sightings(conn, since)

    # ── SSID-based MAC clustering ────────────────────────────────────────────
    clusters = build_ssid_clusters(conn, since)

    # Accumulate combined stats per cluster for the score boost pass
    cluster_combined: dict = {}
    for row in rows:
        cid = clusters.get(row['mac'])
        if not cid:
            continue
        if cid not in cluster_combined:
            cluster_combined[cid] = {
                'sighting_count': 0,
                'locations_seen': 0,
                'first_seen':     row.get('first_seen') or 0,
                'last_seen':      row.get('last_seen')  or 0,
                'avg_rssi':       row.get('avg_rssi')   or -100,
            }
        s = cluster_combined[cid]
        s['sighting_count'] += row.get('sighting_count', 0)
        s['locations_seen']  = max(s['locations_seen'], row.get('locations_seen', 0))
        if row.get('first_seen'):
            s['first_seen'] = min(s['first_seen'], row['first_seen']) if s['first_seen'] else row['first_seen']
        if row.get('last_seen'):
            s['last_seen']  = max(s['last_seen'],  row['last_seen'])
        s['avg_rssi'] = max(s['avg_rssi'], row.get('avg_rssi') or -100)

    # ── Co-occurrence groups ──────────────────────────────────────────────────
    groups = build_cooccurrence_groups(conn, since)

    # ── Score, cluster-boost, and persist each device ────────────────────────
    above_low = 0
    scored = []

    for row in rows:
        row['cluster_id'] = clusters.get(row['mac'])
        row['group_id']   = groups.get(row['mac'])

        _wl = wl_conn or conn
        if dbmod.is_whitelisted(_wl, row['mac']):
            row['threat_score'] = 0.0
        else:
            row['threat_score'] = compute_score(row)

            cid = row['cluster_id']
            if cid and cid in cluster_combined:
                s = cluster_combined[cid]
                boosted = dict(row)
                boosted['sighting_count'] = s['sighting_count']
                boosted['locations_seen'] = s['locations_seen']
                boosted['first_seen']     = s['first_seen']
                boosted['last_seen']      = s['last_seen']
                boosted['avg_rssi']       = s['avg_rssi']
                cluster_score = min(compute_score(boosted) + CLUSTER_BOOST, 1.0)
                if cluster_score > row['threat_score']:
                    row['threat_score'] = cluster_score

        dbmod.upsert_persistence(conn, row)
        scored.append(row)

    # ── Group boost pass — propagate highest score within each group ──────────
    _wl = wl_conn or conn
    group_max: dict = {}
    for row in scored:
        gid = row.get('group_id')
        if gid and not dbmod.is_whitelisted(_wl, row['mac']):
            if row['threat_score'] > group_max.get(gid, 0.0):
                group_max[gid] = row['threat_score']

    for row in scored:
        gid = row.get('group_id')
        if gid and gid in group_max and not dbmod.is_whitelisted(_wl, row['mac']):
            max_in_group = group_max[gid]
            boosted = min(row['threat_score'] + GROUP_BOOST, max_in_group)
            if boosted > row['threat_score']:
                row['threat_score'] = boosted
                dbmod.upsert_persistence(conn, row)

    for row in scored:
        if row['threat_score'] >= T_LOW:
            above_low += 1
            if logf and alert_tracker.should_alert(row['mac'], row['threat_score'], T_LOW):
                write_alert(logf, row)

        if verbose and row['threat_score'] >= T_NORMAL:
            mfr = row.get('manufacturer') or ''
            cid_tag = f'  C{row["cluster_id"]}' if row.get('cluster_id') else ''
            gid_tag = f'  G{row["group_id"]}' if row.get('group_id') else ''
            print(
                f"[analyzer] {row['mac']}  {row['source']:<5}  "
                f"score={row['threat_score']:.2f} ({threat_level(row['threat_score']):<8})  "
                f"rssi={row['avg_rssi']}  seen={row['sighting_count']}  {mfr}{cid_tag}{gid_tag}",
                flush=True
            )

    n_clusters = len(set(cluster_combined.keys()))
    n_groups   = len(set(groups.values()))
    if verbose:
        print(f'[analyzer] {len(rows)} devices, {above_low} above LOW, '
              f'{len(clusters)} MACs in {n_clusters} cluster(s), '
              f'{len(groups)} MACs in {n_groups} group(s)', flush=True)

    if status_path:
        ble_total   = dbmod.count_unique_macs(conn, window_sec, 'ble')
        wifi_total  = dbmod.count_unique_macs(conn, window_sec, 'wifi')
        drone_total = dbmod.count_unique_macs(conn, window_sec, 'drone')
        write_status_json(status_path, scored, ble_total, wifi_total,
                          drone_total, n_clusters, n_groups, window_sec)

    return scored


def main():
    global running, do_analysis

    parser = argparse.ArgumentParser(description='CYT Threat Analyzer')
    parser.add_argument('--db',       required=True, help='SQLite database path')
    parser.add_argument('--log',      help='Alert log file (default: <db>.log)')
    parser.add_argument('--status',   help='JSON status file path')
    parser.add_argument('--interval', type=int, default=30,  help='Analysis interval (seconds)')
    parser.add_argument('--window',   type=int, default=3600, help='Sighting window (seconds)')
    parser.add_argument('--daemon',   action='store_true')
    parser.add_argument('--pidfile',  help='Write PID file')
    parser.add_argument('--once',     action='store_true', help='Run once and exit')
    parser.add_argument('--verbose',  action='store_true')
    args = parser.parse_args()

    log_path = args.log or os.path.splitext(args.db)[0] + '.log'

    if args.daemon:
        daemonize()
    if args.pidfile:
        write_pidfile(args.pidfile)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT,  sig_handler)
    signal.signal(signal.SIGUSR1, sig_handler)
    signal.signal(signal.SIGHUP,  sig_handler)

    conn    = dbmod.open_db(args.db)
    wl_path = os.path.join(os.path.dirname(os.path.abspath(args.db)), 'whitelist.db')
    wl_conn = dbmod.open_whitelist_db(wl_path)

    try:
        logf = open(log_path, 'a')
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logf.write(f'--- CYT analyzer started {ts} ---\n')
        logf.flush()
    except OSError as e:
        logf = None
        if not args.daemon:
            print(f'[analyzer] Warning: cannot open log {log_path}: {e}', flush=True)

    if not args.daemon:
        print(f'[analyzer] Running every {args.interval}s on {args.db}', flush=True)

    tracker = AlertTracker()

    if args.once:
        run_analysis(conn, logf, args.status, args.window, tracker, args.verbose, wl_conn)
    else:
        while running:
            try:
                run_analysis(conn, logf, args.status, args.window, tracker, args.verbose, wl_conn)
            except Exception as e:
                if logf:
                    logf.write(f'[analyzer] Error: {e}\n')
                    logf.flush()
                # Try to reopen DB on error; keep old conn if reopen fails
                try:
                    conn.close()
                except Exception:
                    pass
                new_conn = None
                for _ in range(3):
                    try:
                        new_conn = dbmod.open_db(args.db)
                        break
                    except Exception:
                        time.sleep(1)
                if new_conn is not None:
                    conn = new_conn
            # Sleep in 1-second ticks so SIGTERM is responsive
            for _ in range(args.interval):
                if not running or do_analysis:
                    do_analysis = False
                    break
                time.sleep(1)

    conn.close()
    if logf:
        logf.close()
    if args.pidfile and os.path.exists(args.pidfile):
        os.unlink(args.pidfile)


if __name__ == '__main__':
    main()
