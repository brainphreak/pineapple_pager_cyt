#!/mmc/usr/bin/python3
"""
web_server.py — CYT Live Dashboard Web Server
Serves a dark-theme auto-refreshing dashboard on port 8080.

Endpoints:
    GET /            — Live HTML dashboard (auto-refreshes every 5s via JS)
    GET /api/status  — status.json as JSON
    GET /api/devices — Live device list from DB (JSON)
    GET /report      — Generate and serve latest HTML report

Usage:
    web_server.py --db PATH --status PATH [--port N] [--daemon] [--pidfile PATH]
"""
import argparse
import json
import os
import signal
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db as dbmod

running  = True
_args    = None
_conn    = None
_wl_conn = None


# ── Signal handling ────────────────────────────────────────────────────────────

def sig_handler(sig, frame):
    global running
    running = False
    sys.exit(0)


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


# ── Helpers ────────────────────────────────────────────────────────────────────

def threat_level(score: float) -> str:
    if score >= 0.80: return 'CRITICAL'
    if score >= 0.60: return 'HIGH'
    if score >= 0.40: return 'MEDIUM'
    if score >= 0.20: return 'LOW'
    return 'NORMAL'


def threat_color(score: float) -> str:
    if score >= 0.80: return '#ff4444'
    if score >= 0.60: return '#ff8800'
    if score >= 0.40: return '#ffcc00'
    if score >= 0.20: return '#44cc44'
    return '#888888'


def fmt_ts(ts) -> str:
    if not ts: return '—'
    return datetime.fromtimestamp(ts).strftime('%H:%M:%S')


def fmt_dur(first, last) -> str:
    if not first or not last: return '—'
    s = last - first
    if s < 60:   return f'{s}s'
    if s < 3600: return f'{s // 60}m {s % 60}s'
    return f'{s // 3600}h {(s % 3600) // 60}m'


def get_status() -> dict:
    """Read status.json, return dict (or empty dict on error)."""
    try:
        with open(_args.status, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def get_devices(limit: int = 100) -> list:
    """Query persistence table, return list of dicts."""
    global _conn
    try:
        rows = dbmod.query_persistence(_conn, limit=limit)
        rows.sort(key=lambda d: d.get('threat_score', 0), reverse=True)
        return rows
    except Exception:
        try:
            _conn = dbmod.open_db(_args.db)
            rows = dbmod.query_persistence(_conn, limit=limit)
            rows.sort(key=lambda d: d.get('threat_score', 0), reverse=True)
            return rows
        except Exception:
            return []


# ── HTML Dashboard ─────────────────────────────────────────────────────────────

DASHBOARD_HTML = '''\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYT Live Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0a0a0a;color:#ccc;font-family:monospace,monospace;font-size:13px;padding:16px}
  h1{color:#fff;font-size:1.3em;border-bottom:1px solid #222;padding-bottom:8px;margin-bottom:12px}
  .meta{color:#555;font-size:0.85em;margin-bottom:16px}
  #status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#44cc44;margin-right:6px;vertical-align:middle}
  .cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px}
  .card{background:#111;border:1px solid #222;border-radius:6px;padding:10px 18px;min-width:90px;text-align:center}
  .card .num{font-size:1.9em;font-weight:bold;line-height:1.1}
  .card .lbl{color:#555;font-size:0.78em;margin-top:4px}
  .c-crit{color:#ff4444}.c-high{color:#ff8800}.c-med{color:#ffcc00}
  .c-low{color:#44cc44}.c-ble{color:#00ccff}.c-wifi{color:#cc88ff}.c-drone{color:#ff6600}
  .c-cluster{color:#cc44ff}.c-group{color:#ff8800}
  .cbadge{font-size:0.72em;border:1px solid #ff880044;color:#ff8800;padding:0 3px;border-radius:2px;margin-left:4px;vertical-align:middle}
  .warn{background:#2d1000;border:1px solid #ff6600;border-radius:6px;padding:10px 14px;
        color:#ff8800;margin-bottom:16px;font-weight:bold;display:none}
  table{border-collapse:collapse;width:100%;margin-top:4px}
  th{background:#111;color:#666;padding:6px 8px;text-align:left;border-bottom:1px solid #1f1f1f;white-space:nowrap;font-size:0.8em}
  td{padding:5px 8px;border-bottom:1px solid #111;white-space:nowrap}
  tr:hover td{background:#0f0f0f}
  .wl-btn{background:none;border:1px solid #333;color:#666;padding:2px 7px;border-radius:3px;
          cursor:pointer;font-family:monospace;font-size:11px}
  .wl-btn:hover{border-color:#ff8800;color:#ff8800}
  .wl-section{margin-top:30px}
  .wl-row{display:flex;align-items:center;gap:12px;padding:5px 0;border-bottom:1px solid #111;font-size:0.85em}
  .wl-mac{color:#88ccff;font-family:monospace}
  .wl-name{color:#888}
  .rm-btn{background:none;border:1px solid #333;color:#666;padding:1px 8px;border-radius:3px;
          cursor:pointer;font-family:monospace;font-size:11px}
  .rm-btn:hover{border-color:#ff4444;color:#ff4444}
  code{background:#1a1a1a;padding:1px 4px;border-radius:3px;color:#88ccff;font-size:0.9em}
  .badge{display:inline-block;padding:1px 7px;border-radius:3px;font-size:0.78em;font-weight:bold;letter-spacing:.04em}
  .footer{margin-top:32px;color:#333;font-size:0.8em;border-top:1px solid #161616;padding-top:10px}
  .section-title{color:#555;font-size:0.85em;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
  #err{color:#ff4444;font-size:0.8em;display:none;margin-bottom:8px}
  a{color:#888;text-decoration:none}
  .btn{background:#1a1a1a;border:1px solid #333;color:#aaa;padding:4px 12px;border-radius:4px;cursor:pointer;font-family:monospace;font-size:12px}
  .btn:hover{background:#222;color:#fff}
</style>
</head>
<body>
<h1><span id="status-dot"></span>&#x1F50D; Chasing Your Tail &mdash; Live Dashboard</h1>
<div class="meta" id="meta">Connecting&hellip;</div>
<div class="warn" id="warn"></div>
<div id="err">&#x26A0; API error &mdash; retrying&hellip;</div>

<div class="cards" id="cards">
  <div class="card"><div class="num" id="c-total">—</div><div class="lbl">Total</div></div>
  <div class="card"><div class="num c-ble" id="c-ble">—</div><div class="lbl">BLE</div></div>
  <div class="card"><div class="num c-wifi" id="c-wifi">—</div><div class="lbl">WiFi</div></div>
  <div class="card"><div class="num c-drone" id="c-drone">—</div><div class="lbl">Drones</div></div>
  <div class="card"><div class="num c-cluster" id="c-cluster">—</div><div class="lbl">Clusters</div></div>
  <div class="card"><div class="num c-group" id="c-group">—</div><div class="lbl">Groups</div></div>
  <div class="card"><div class="num c-crit" id="c-crit">—</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num c-high" id="c-high">—</div><div class="lbl">High</div></div>
  <div class="card"><div class="num c-med" id="c-med">—</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num c-low" id="c-low">—</div><div class="lbl">Low</div></div>
</div>

<div style="margin-bottom:10px;display:flex;align-items:center;gap:10px">
  <span class="section-title">Threat Devices</span>
  <select id="src-filter" class="btn" onchange="applyFilter()">
    <option value="all">All sources</option>
    <option value="ble">BLE only</option>
    <option value="wifi">WiFi only</option>
    <option value="drone">Drone only</option>
    <option value="clustered">Clustered MACs</option>
  </select>
  <select id="lvl-filter" class="btn" onchange="applyFilter()">
    <option value="all">All levels</option>
    <option value="CRITICAL">Critical+</option>
    <option value="HIGH">High+</option>
    <option value="MEDIUM">Medium+</option>
    <option value="LOW">Low+</option>
  </select>
  <a href="/report" target="_blank" class="btn">&#x1F4C4; HTML Report</a>
</div>

<table id="dev-table">
<thead>
<tr>
  <th>Level</th><th>MAC</th><th>Src</th><th>Score</th>
  <th>RSSI</th><th>Sightings</th><th>Duration</th>
  <th>First</th><th>Last</th><th>Manufacturer</th><th>Name</th><th></th>
</tr>
</thead>
<tbody id="dev-body">
  <tr><td colspan="12" style="color:#444;text-align:center;padding:20px">Loading&hellip;</td></tr>
</tbody>
</table>

<div class="wl-section">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
    <span class="section-title">Whitelist</span>
    <span style="color:#555;font-size:0.8em">Whitelisted devices are ignored by the threat scorer</span>
  </div>
  <div id="wl-body"><span style="color:#444;font-size:0.85em">None</span></div>
</div>

<div class="footer">
  Chasing Your Tail &mdash; Hak5 WiFi Pineapple Pager &nbsp;|&nbsp;
  Auto-refresh every 5s &nbsp;|&nbsp;
  <span id="last-update">—</span>
</div>

<script>
const LEVEL_ORDER = {CRITICAL:4,HIGH:3,MEDIUM:2,LOW:1,NORMAL:0};
const LEVEL_COLOR = {
  CRITICAL:'#ff4444', HIGH:'#ff8800', MEDIUM:'#ffcc00',
  LOW:'#44cc44', NORMAL:'#888'
};
const MIN_SCORE = {all:-1, CRITICAL:0.80, HIGH:0.60, MEDIUM:0.40, LOW:0.20};

let allDevices = [];
let whitelist  = new Set();

function threatLevel(s) {
  if (s >= 0.80) return 'CRITICAL';
  if (s >= 0.60) return 'HIGH';
  if (s >= 0.40) return 'MEDIUM';
  if (s >= 0.20) return 'LOW';
  return 'NORMAL';
}

function fmtDur(first, last) {
  if (!first || !last) return '—';
  const s = last - first;
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s/60) + 'm ' + (s%60) + 's';
  return Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';
}

function fmtTs(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toTimeString().slice(0,8);
}

async function addWhitelist(mac, name) {
  try {
    await fetch('/api/whitelist', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({mac, name})
    });
    whitelist.add(mac.toUpperCase());
    renderWhitelist(await (await fetch('/api/whitelist')).json());
    applyFilter();
  } catch(e) { alert('Whitelist error: ' + e); }
}

async function removeWhitelist(mac) {
  try {
    await fetch('/api/whitelist/' + encodeURIComponent(mac), {method:'DELETE'});
    whitelist.delete(mac.toUpperCase());
    renderWhitelist(await (await fetch('/api/whitelist')).json());
    applyFilter();
  } catch(e) { alert('Whitelist error: ' + e); }
}

function renderWhitelist(entries) {
  whitelist = new Set(entries.map(e => e.mac.toUpperCase()));
  const el = document.getElementById('wl-body');
  if (!entries.length) {
    el.innerHTML = '<span style="color:#444;font-size:0.85em">None &mdash; whitelisted devices are hidden from the threat table</span>';
    applyFilter();
    return;
  }
  el.innerHTML = entries.map(e => {
    const dev    = allDevices.find(d => d.mac.toUpperCase() === e.mac.toUpperCase());
    const mfr    = (dev ? (dev.manufacturer || e.name) : e.name) || '—';
    const src    = dev ? `<span style="color:${dev.source==='ble'?'#00ccff':dev.source==='drone'?'#ff6600':'#cc88ff'}">${dev.source.toUpperCase()}</span>` : '';
    const last   = dev ? `<span style="color:#555">last ${fmtTs(dev.last_seen)}</span>` : '';
    const score  = dev ? `<span style="color:#555">${dev.threat_score.toFixed(2)}</span>` : '';
    return `<div class="wl-row">
      <span class="wl-mac">${e.mac}</span>
      ${src}
      <span class="wl-name">${mfr.replace(/</g,'&lt;')}</span>
      ${score}${last}
      <button class="rm-btn" onclick="removeWhitelist('${e.mac}')">Remove</button>
    </div>`;
  }).join('');
  applyFilter();
}

function applyFilter() {
  const src = document.getElementById('src-filter').value;
  const lvl = document.getElementById('lvl-filter').value;
  const minS = lvl === 'all' ? -1 : MIN_SCORE[lvl];
  const filtered = allDevices.filter(d => {
    if (whitelist.has(d.mac.toUpperCase())) return false;
    if (src === 'clustered') { if (!d.cluster_id) return false; }
    else if (src !== 'all' && d.source !== src) return false;
    if (d.threat_score < minS) return false;
    return true;
  });
  renderTable(filtered);
}

function renderTable(devices) {
  const tbody = document.getElementById('dev-body');
  if (!devices.length) {
    tbody.innerHTML = '<tr><td colspan="12" style="color:#444;text-align:center;padding:20px">No devices match filter</td></tr>';
    return;
  }
  tbody.innerHTML = devices.map(d => {
    const lvl      = threatLevel(d.threat_score);
    const color    = LEVEL_COLOR[lvl];
    const dur      = fmtDur(d.first_seen, d.last_seen);
    const mfr      = (d.manufacturer || '—').replace(/</g,'&lt;');
    const nm       = (d.name || '—').replace(/</g,'&lt;');
    const srcColor = d.source==='ble' ? '#00ccff' : d.source==='drone' ? '#ff6600' : '#cc88ff';
    const clusterBadge = d.cluster_id ? `<span class="cbadge">C${d.cluster_id}</span>` : '';
    const groupBadge   = d.group_id   ? `<span class="cbadge" style="border-color:#ff880044;color:#ff8800">G${d.group_id}</span>` : '';
    const wlBtn = `<button class="wl-btn" onclick="addWhitelist('${d.mac}','${(d.manufacturer||'').replace(/'/g,'')}')">Whitelist</button>`;
    return `<tr>
      <td><span class="badge" style="color:${color};border:1px solid ${color}22;background:${color}11">${lvl}</span></td>
      <td><code>${d.mac}</code>${clusterBadge}${groupBadge}</td>
      <td style="color:${srcColor}">${d.source.toUpperCase()}</td>
      <td style="color:${color};font-weight:bold">${d.threat_score.toFixed(2)}</td>
      <td>${d.avg_rssi}</td>
      <td>${d.sighting_count}</td>
      <td>${dur}</td>
      <td>${fmtTs(d.first_seen)}</td>
      <td>${fmtTs(d.last_seen)}</td>
      <td style="color:#888">${mfr}</td>
      <td style="color:#aaa">${nm}</td>
      <td>${wlBtn}</td>
    </tr>`;
  }).join('');
}

async function refresh() {
  try {
    const [statusRes, devRes, wlRes] = await Promise.all([
      fetch('/api/status'),
      fetch('/api/devices'),
      fetch('/api/whitelist')
    ]);

    if (!statusRes.ok || !devRes.ok) throw new Error('HTTP error');
    document.getElementById('err').style.display = 'none';
    document.getElementById('status-dot').style.background = '#44cc44';

    const st   = await statusRes.json();
    const devs = await devRes.json();
    const wl   = await wlRes.json();
    allDevices = devs;
    renderWhitelist(wl);

    // Update meta
    const now = new Date().toLocaleTimeString();
    const win = st.window_sec ? Math.round(st.window_sec / 60) + ' min window' : '';
    document.getElementById('meta').textContent =
      'Updated: ' + now + (win ? '  |  ' + win : '');
    document.getElementById('last-update').textContent = 'Last update: ' + now;

    // Warning banner
    const nHigh = (st.critical || 0) + (st.high || 0);
    const warnEl = document.getElementById('warn');
    if (nHigh > 0) {
      warnEl.style.display = 'block';
      warnEl.textContent = '⚠ ' + nHigh + ' HIGH/CRITICAL threat device(s) detected';
    } else {
      warnEl.style.display = 'none';
    }

    // Cards — always computed from live device list, not stale status.json
    const active = devs.filter(d => !whitelist.has(d.mac.toUpperCase()));
    document.getElementById('c-total').textContent   = active.length;
    document.getElementById('c-ble').textContent     = active.filter(d=>d.source==='ble').length;
    document.getElementById('c-wifi').textContent    = active.filter(d=>d.source==='wifi').length;
    document.getElementById('c-drone').textContent   = active.filter(d=>d.source==='drone').length;
    document.getElementById('c-cluster').textContent = new Set(active.filter(d=>d.cluster_id).map(d=>d.cluster_id)).size;
    document.getElementById('c-group').textContent   = new Set(active.filter(d=>d.group_id).map(d=>d.group_id)).size;
    document.getElementById('c-crit').textContent    = active.filter(d=>d.threat_score>=0.80).length;
    document.getElementById('c-high').textContent    = active.filter(d=>d.threat_score>=0.60&&d.threat_score<0.80).length;
    document.getElementById('c-med').textContent     = active.filter(d=>d.threat_score>=0.40&&d.threat_score<0.60).length;
    document.getElementById('c-low').textContent     = active.filter(d=>d.threat_score>=0.20&&d.threat_score<0.40).length;

    applyFilter();
  } catch(e) {
    document.getElementById('err').style.display = 'block';
    document.getElementById('status-dot').style.background = '#ff4444';
  }
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
'''


# ── HTTP Handler ───────────────────────────────────────────────────────────────

class CYTHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # silence default access log

    def send_json(self, data, code=200):
        body = json.dumps(data, default=str).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str, code=200):
        body = html.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        if path == '/':
            self.send_html(DASHBOARD_HTML)

        elif path == '/api/status':
            self.send_json(get_status())

        elif path == '/api/devices':
            qs    = parse_qs(parsed.query)
            limit = int(qs.get('limit', [100])[0])
            self.send_json(get_devices(limit))

        elif path == '/api/whitelist':
            try:
                self.send_json(dbmod.get_whitelist(_wl_conn))
            except Exception as e:
                self.send_json({'error': str(e)}, code=500)

        elif path == '/report':
            # Generate an in-memory HTML report and serve it
            try:
                import reporter as rep
                conn_r = dbmod.open_db(_args.db)
                try:
                    data = rep.build_data(conn_r, window_sec=3600, min_score=0.0)
                finally:
                    conn_r.close()
                import types
                rep.args = types.SimpleNamespace(min_score=0.0)
                import tempfile
                with tempfile.NamedTemporaryFile(suffix='.html', delete=False, mode='w') as tf:
                    tmp_path = tf.name
                rep.write_html(data, tmp_path)
                with open(tmp_path, 'r') as f:
                    html = f.read()
                os.unlink(tmp_path)
                self.send_html(html)
            except Exception as e:
                self.send_html(f'<pre>Report error: {e}</pre>', code=500)

        else:
            self.send_html('<h3>404 Not Found</h3>', code=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == '/api/whitelist':
            try:
                length = int(self.headers.get('Content-Length', 0))
                body   = json.loads(self.rfile.read(length))
                mac    = body.get('mac', '').strip()
                name   = body.get('name', '').strip()
                if not mac:
                    self.send_json({'error': 'mac required'}, code=400)
                    return
                dbmod.add_to_whitelist(_wl_conn, mac, name)
                self.send_json({'ok': True, 'mac': mac.upper()})
            except Exception as e:
                self.send_json({'error': str(e)}, code=500)
        else:
            self.send_html('<h3>404</h3>', code=404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        # /api/whitelist/AA:BB:CC:DD:EE:FF
        if parsed.path.startswith('/api/whitelist/'):
            mac = parsed.path[len('/api/whitelist/'):].strip()
            try:
                dbmod.remove_from_whitelist(_wl_conn, mac)
                self.send_json({'ok': True, 'mac': mac.upper()})
            except Exception as e:
                self.send_json({'error': str(e)}, code=500)
        else:
            self.send_html('<h3>404</h3>', code=404)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    global _args, _conn, _wl_conn

    parser = argparse.ArgumentParser(description='CYT Live Dashboard Web Server')
    parser.add_argument('--db',      required=True, help='SQLite database path')
    parser.add_argument('--status',  required=True, help='status.json path')
    parser.add_argument('--port',    type=int, default=8080, help='HTTP port (default 8080)')
    parser.add_argument('--daemon',  action='store_true', help='Fork to background')
    parser.add_argument('--pidfile', help='Write PID to file')
    _args = parser.parse_args()

    _conn    = dbmod.open_db(_args.db)
    wl_path  = os.path.join(os.path.dirname(os.path.abspath(_args.db)), 'whitelist.db')
    _wl_conn = dbmod.open_whitelist_db(wl_path)

    if _args.daemon:
        daemonize()

    if _args.pidfile:
        write_pidfile(_args.pidfile)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT,  sig_handler)

    server = HTTPServer(('0.0.0.0', _args.port), CYTHandler)
    server.timeout = 2

    if not _args.daemon:
        print(f'[web] CYT dashboard at http://0.0.0.0:{_args.port}/', flush=True)

    while running:
        server.handle_request()

    server.server_close()
    if _args.pidfile and os.path.exists(_args.pidfile):
        os.unlink(_args.pidfile)


if __name__ == '__main__':
    main()
