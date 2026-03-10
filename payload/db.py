"""
db.py — SQLite database layer for Chasing Your Tail
Uses DELETE journal mode for reliable multi-process access on embedded flash.
"""
import sqlite3
import time
import os


def open_db(path: str) -> sqlite3.Connection:
    """Open (or create) the CYT database and ensure schema exists."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=30,
                           isolation_level=None)  # autocommit: no stale WAL reads
    conn.row_factory = sqlite3.Row
    # Pragmas must be set outside a transaction.
    # Use DELETE journal (no WAL files) — more reliable on embedded flash.
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=500")
    conn.execute("PRAGMA busy_timeout=30000")   # 30 s retry on locked DB
    # Create schema in a single transaction
    conn.execute("BEGIN")
    conn.execute("""CREATE TABLE IF NOT EXISTS sightings (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        mac         TEXT    NOT NULL,
        source      TEXT    NOT NULL,
        rssi        INTEGER,
        name        TEXT,
        manufacturer TEXT,
        adv_flags   TEXT,
        ssid_probes TEXT,
        lat         REAL    DEFAULT 0,
        lon         REAL    DEFAULT 0,
        timestamp   INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sightings_mac  ON sightings(mac)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sightings_time ON sightings(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sightings_src  ON sightings(source, timestamp)")
    conn.execute("""CREATE TABLE IF NOT EXISTS persistence (
        mac             TEXT NOT NULL,
        source          TEXT NOT NULL,
        first_seen      INTEGER,
        last_seen       INTEGER,
        sighting_count  INTEGER,
        avg_rssi        INTEGER,
        locations_seen  INTEGER DEFAULT 0,
        threat_score    REAL DEFAULT 0.0,
        name            TEXT,
        manufacturer    TEXT,
        ssid_set        TEXT,
        cluster_id      INTEGER,
        group_id        INTEGER,
        PRIMARY KEY (mac, source)
    )""")
    conn.execute("COMMIT")
    # Migrate existing DBs — ignore errors when column already exists
    for col, defn in [('ssid_set', 'TEXT'), ('cluster_id', 'INTEGER'), ('group_id', 'INTEGER')]:
        try:
            conn.execute(f'ALTER TABLE persistence ADD COLUMN {col} {defn}')
        except Exception:
            pass
    return conn


def open_whitelist_db(path: str) -> sqlite3.Connection:
    """Open (or create) the persistent whitelist database."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=30,
                           isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("BEGIN")
    conn.execute("""CREATE TABLE IF NOT EXISTS whitelist (
        mac     TEXT PRIMARY KEY,
        name    TEXT,
        added   INTEGER
    )""")
    conn.execute("COMMIT")
    return conn


def insert_sighting(conn: sqlite3.Connection,
                    mac: str, source: str, rssi: int,
                    name: str = '', manufacturer: str = '',
                    adv_flags: str = '', ssid_probes: str = '',
                    lat: float = 0.0, lon: float = 0.0,
                    timestamp: int = None) -> None:
    """Insert a single sighting (auto-committed with isolation_level=None)."""
    if timestamp is None:
        timestamp = int(time.time())
    try:
        conn.execute(
            "INSERT INTO sightings"
            "(mac,source,rssi,name,manufacturer,adv_flags,ssid_probes,lat,lon,timestamp)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (mac, source, rssi,
             name or None, manufacturer or None, adv_flags or None,
             ssid_probes or None, lat, lon, timestamp)
        )
    except Exception:
        pass


def insert_sightings_batch(conn: sqlite3.Connection, sightings: list) -> None:
    """Insert multiple sightings in one transaction (much faster)."""
    if not sightings:
        return
    try:
        conn.execute("BEGIN")
        conn.executemany(
            "INSERT INTO sightings"
            "(mac,source,rssi,name,manufacturer,adv_flags,ssid_probes,lat,lon,timestamp)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(s['mac'], s['source'], s.get('rssi', 0),
              s.get('name') or None, s.get('manufacturer') or None,
              s.get('adv_flags') or None, s.get('ssid_probes') or None,
              s.get('lat', 0.0), s.get('lon', 0.0),
              s.get('timestamp') or int(time.time()))
             for s in sightings]
        )
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass


def aggregate_sightings(conn: sqlite3.Connection,
                         since: int, limit: int = 1024) -> list:
    """Aggregate sightings since epoch `since` by (mac, source).
    Retries up to 3 times on transient WAL-read errors."""
    query = """
        SELECT mac, source,
               MIN(timestamp)  AS first_seen,
               MAX(timestamp)  AS last_seen,
               COUNT(*)        AS sighting_count,
               CAST(AVG(rssi) AS INTEGER) AS avg_rssi,
               COUNT(DISTINCT
                   CASE WHEN lat != 0 OR lon != 0
                        THEN CAST(lat*1000 AS INTEGER)||','||CAST(lon*1000 AS INTEGER)
                        ELSE NULL END
               )               AS locations_seen,
               MAX(name)       AS name,
               MAX(manufacturer) AS manufacturer,
               GROUP_CONCAT(DISTINCT ssid_probes) AS ssid_set
        FROM sightings
        WHERE timestamp >= ?
        GROUP BY mac, source
        ORDER BY sighting_count DESC
        LIMIT ?
    """
    last_exc = None
    for attempt in range(3):
        try:
            rows = conn.execute(query, (since, limit)).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            last_exc = e
            time.sleep(0.5 * (attempt + 1))
    raise last_exc


def upsert_persistence(conn: sqlite3.Connection, row: dict) -> None:
    try:
        conn.execute("""
            INSERT INTO persistence
                (mac,source,first_seen,last_seen,sighting_count,
                 avg_rssi,locations_seen,threat_score,name,manufacturer,
                 ssid_set,cluster_id,group_id)
            VALUES (:mac,:source,:first_seen,:last_seen,:sighting_count,
                    :avg_rssi,:locations_seen,:threat_score,:name,:manufacturer,
                    :ssid_set,:cluster_id,:group_id)
            ON CONFLICT(mac,source) DO UPDATE SET
                first_seen     = excluded.first_seen,
                last_seen      = excluded.last_seen,
                sighting_count = excluded.sighting_count,
                avg_rssi       = excluded.avg_rssi,
                locations_seen = excluded.locations_seen,
                threat_score   = excluded.threat_score,
                name           = COALESCE(excluded.name, persistence.name),
                manufacturer   = COALESCE(excluded.manufacturer, persistence.manufacturer),
                ssid_set       = COALESCE(excluded.ssid_set, persistence.ssid_set),
                cluster_id     = excluded.cluster_id,
                group_id       = excluded.group_id
        """, {**row,
              'ssid_set':   row.get('ssid_set'),
              'cluster_id': row.get('cluster_id'),
              'group_id':   row.get('group_id')})
        # auto-committed with isolation_level=None
    except Exception:
        pass


def query_persistence(conn: sqlite3.Connection,
                       limit: int = 100,
                       source_filter: str = None) -> list:
    """Return persistence rows ordered by threat_score DESC."""
    if source_filter and source_filter != 'all':
        rows = conn.execute(
            "SELECT * FROM persistence WHERE source=? ORDER BY threat_score DESC LIMIT ?",
            (source_filter, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM persistence ORDER BY threat_score DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def is_whitelisted(conn: sqlite3.Connection, mac: str) -> bool:
    r = conn.execute("SELECT 1 FROM whitelist WHERE mac=?", (mac.upper(),)).fetchone()
    return r is not None


def add_to_whitelist(conn: sqlite3.Connection, mac: str, name: str = '') -> None:
    conn.execute(
        "INSERT OR REPLACE INTO whitelist (mac, name, added) VALUES (?, ?, ?)",
        (mac.upper(), name, int(time.time()))
    )


def remove_from_whitelist(conn: sqlite3.Connection, mac: str) -> None:
    conn.execute("DELETE FROM whitelist WHERE mac=?", (mac.upper(),))


def get_whitelist(conn: sqlite3.Connection) -> list:
    rows = conn.execute(
        "SELECT mac, name, added FROM whitelist ORDER BY added DESC"
    ).fetchall()
    return [{'mac': r[0], 'name': r[1], 'added': r[2]} for r in rows]


def count_unique_macs(conn: sqlite3.Connection,
                       window_sec: int,
                       source: str = None) -> int:
    since = int(time.time()) - window_sec
    if source:
        r = conn.execute(
            "SELECT COUNT(DISTINCT mac) FROM sightings WHERE timestamp>=? AND source=?",
            (since, source)
        ).fetchone()
    else:
        r = conn.execute(
            "SELECT COUNT(DISTINCT mac) FROM sightings WHERE timestamp>=?",
            (since,)
        ).fetchone()
    return r[0] if r else 0
