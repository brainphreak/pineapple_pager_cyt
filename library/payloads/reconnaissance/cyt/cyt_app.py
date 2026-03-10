#!/mmc/usr/bin/python3
"""
cyt_app.py — Unified pagerctl GUI for Chasing Your Tail

Screens:
  0. Startup menu  — title, daemon status, options
  1. Device list   — scrollable threat device table
  2. Device detail — full info on selected device
  3. Exit menu     — keep running / stop CYT / stop web / back

Exit codes:
  0  — normal exit (daemons keep running)
  1  — stop all daemons before exit
  99 — restart startup menu (loop in payload.sh)
"""

import argparse
import os
import signal
import subprocess
import sys
import threading
import time

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PAYLOAD_DIR)
sys.path.insert(0, os.path.join(PAYLOAD_DIR, 'lib'))

import db as dbmod
from pagerctl import Pager

# ── Font ──────────────────────────────────────────────────────────
FONT_TTF = os.path.join(PAYLOAD_DIR, 'fonts', 'DejaVuSansMono.ttf')
FONT_MD  = 18   # menus, detail view, headers
FONT_SM  = 18   # status bar, device rows, control bar

# ── Daemon PID paths ──────────────────────────────────────────────
BLE_PID  = os.path.join(PAYLOAD_DIR, 'ble.pid')
WIFI_PID = os.path.join(PAYLOAD_DIR, 'wifi.pid')
ANA_PID  = os.path.join(PAYLOAD_DIR, 'analyzer.pid')
WEB_PID  = os.path.join(PAYLOAD_DIR, 'web.pid')

DB_PATH    = os.path.join(PAYLOAD_DIR, 'cyt.db')
WL_PATH    = os.path.join(PAYLOAD_DIR, 'whitelist.db')
CYT_LOG    = os.path.join(PAYLOAD_DIR, 'cyt.log')
STATUS_JSON = os.path.join(PAYLOAD_DIR, 'status.json')

# ── Layout ────────────────────────────────────────────────────────
W, H      = 480, 222
STATUS_H  = 22
CTRL_H    = 22
ROW_H     = 24
LIST_Y    = STATUS_H + 1
LIST_H    = H - STATUS_H - CTRL_H - 2
ROWS_VIS  = LIST_H // ROW_H    # ~8 rows

# ── Colors ────────────────────────────────────────────────────────
BLACK    = 0x0000
WHITE    = 0xFFFF
RED      = 0xF800
ORANGE   = 0xFD20
YELLOW   = 0xFFE0
GREEN    = 0x07E0
CYAN     = 0x07FF
BLUE     = 0x001F
GRAY     = 0x8410
DARKGRAY = 0x2104
NAVY     = 0x000F
DKGREEN  = 0x03E0


# ── Helpers ───────────────────────────────────────────────────────

def pid_alive(path):
    try:
        pid = int(open(path).read().strip())
        os.kill(pid, 0)
        return pid
    except Exception:
        return None


def daemon_status():
    return {
        'ble':      pid_alive(BLE_PID),
        'wifi':     pid_alive(WIFI_PID),
        'analyzer': pid_alive(ANA_PID),
        'web':      pid_alive(WEB_PID),
        'gps':      _gps_fix(),
    }


def _gps_fix():
    """Return True if gpsd is running and has a valid fix."""
    try:
        import socket, json
        s = socket.create_connection(('127.0.0.1', 2947), timeout=0.3)
        s.sendall(b'?WATCH={"enable":true,"json":true}\n?POLL;\n')
        data = b''
        s.settimeout(0.3)
        for _ in range(8):
            try: data += s.recv(4096)
            except Exception: break
        s.close()
        for line in data.decode(errors='ignore').splitlines():
            try:
                obj = json.loads(line)
                if obj.get('class') == 'TPV' and obj.get('mode', 0) >= 2:
                    return True
            except Exception:
                pass
    except Exception:
        pass
    return False


def cyt_running():
    st = daemon_status()
    return bool(st['ble'] or st['wifi'] or st['analyzer'])


def kill_daemon(pidfile):
    pid = pid_alive(pidfile)
    if pid:
        try:
            os.kill(pid, 15)
        except Exception:
            pass
    try:
        os.remove(pidfile)
    except Exception:
        pass


def stop_all():
    for f in (BLE_PID, WIFI_PID, ANA_PID, WEB_PID):
        kill_daemon(f)


def _wait_pidfile(path, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pid_alive(path):
            return True
        time.sleep(0.1)
    return False


def start_daemons(with_web=True, db_path=DB_PATH):
    """Start CYT daemons if not already running."""
    python = '/mmc/usr/bin/python3'
    env = os.environ.copy()

    if not pid_alive(BLE_PID):
        subprocess.Popen([python, os.path.join(PAYLOAD_DIR, 'ble_scanner.py'),
                          '--db', db_path, '--daemon', '--pidfile', BLE_PID],
                         env=env)
        _wait_pidfile(BLE_PID, 3.0)

    if not pid_alive(WIFI_PID):
        subprocess.Popen([python, os.path.join(PAYLOAD_DIR, 'wifi_scanner.py'),
                          '--db', db_path, '--iface', 'wlan0mon', '--daemon', '--pidfile', WIFI_PID],
                         env=env)
        _wait_pidfile(WIFI_PID, 3.0)

    if not pid_alive(ANA_PID):
        subprocess.Popen([python, os.path.join(PAYLOAD_DIR, 'analyzer.py'),
                          '--db', db_path, '--log', CYT_LOG, '--status', STATUS_JSON,
                          '--interval', '30', '--window', '3600',
                          '--daemon', '--pidfile', ANA_PID],
                         env=env)
        _wait_pidfile(ANA_PID, 3.0)

    if with_web and not pid_alive(WEB_PID):
        subprocess.Popen([python, os.path.join(PAYLOAD_DIR, 'web_server.py'),
                          '--db', db_path, '--status', STATUS_JSON,
                          '--port', '8080', '--daemon', '--pidfile', WEB_PID],
                         env=env)
        _wait_pidfile(WEB_PID, 2.0)


def threat_color(score):
    if score >= 0.80: return RED
    if score >= 0.60: return ORANGE
    if score >= 0.40: return YELLOW
    if score >= 0.20: return GREEN
    return GRAY


def threat_label(score):
    if score >= 0.80: return 'C'
    if score >= 0.60: return 'H'
    if score >= 0.40: return 'M'
    if score >= 0.20: return 'L'
    return 'N'


# ════════════════════════════════════════════════════════════════════
#  Main app class
# ════════════════════════════════════════════════════════════════════

class CYTApp:

    def __init__(self, db_path, limit):
        self.db_path = db_path
        self.wl_path = WL_PATH
        self.limit   = limit
        self.running = True

        signal.signal(signal.SIGTERM, self._sig)
        signal.signal(signal.SIGINT,  self._sig)
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)  # auto-reap daemon child processes

        self.gfx = Pager()
        self.gfx.init()
        self.gfx.set_rotation(270)
        self.gfx.screen_on()

        # Background data cache — keeps UI thread from blocking on DB writes
        self._cache = {'all_devs': [], 'ble_total': 0, 'wifi_total': 0, 'version': 0,
                       'wl_macs': set(), 'wl_entries': []}
        self._cache_lock = threading.Lock()

        # Vibration alert state — tracks highest alerted level per MAC
        # Levels: 0=none, 1=medium, 2=high, 3=critical
        self._alerted   = {}   # mac -> alert level already triggered
        self._vib_queue = []   # list of 'critical'/'high'/'medium' pending vibrations
        self._vib_lock  = threading.Lock()

        self._fetcher = threading.Thread(target=self._fetch_loop, daemon=True)
        self._fetcher.start()

    def _sig(self, sig, frame):
        self.running = False

    _tw_cache = {}   # class-level text width cache

    def _txt(self, x, y, text, color, size=None):
        self.gfx.draw_ttf(x, y, str(text), color, FONT_TTF, size or FONT_MD)

    def _tw(self, text, size=None):
        key = (str(text), size or FONT_MD)
        if key not in CYTApp._tw_cache:
            if len(CYTApp._tw_cache) > 512:
                CYTApp._tw_cache.clear()
            CYTApp._tw_cache[key] = self.gfx.ttf_width(str(text), FONT_TTF, size or FONT_MD)
        return CYTApp._tw_cache[key]

    def _fit(self, text, avail, size=None):
        """Truncate text to fit within avail pixels using binary search."""
        if not text:
            return ''
        if self._tw(text, size) <= avail:
            return text
        lo, hi = 0, len(text)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._tw(text[:mid], size) <= avail:
                lo = mid
            else:
                hi = mid - 1
        return text[:lo]

    def _fetch_loop(self):
        """Background DB fetcher — never blocks the UI thread."""
        conn    = None
        wl_conn = None
        while self.running:
            try:
                if conn is None:
                    conn = dbmod.open_db(self.db_path)
                if wl_conn is None:
                    wl_conn = dbmod.open_whitelist_db(self.wl_path)
                all_devs   = dbmod.query_persistence(conn, limit=self.limit * 2)
                ble_total  = dbmod.count_unique_macs(conn, 3600, 'ble')
                wifi_total = dbmod.count_unique_macs(conn, 3600, 'wifi')
                wl_entries = dbmod.get_whitelist(wl_conn)
                wl_macs    = set(e['mac'].upper() for e in wl_entries)
                with self._cache_lock:
                    self._cache['all_devs']    = all_devs
                    self._cache['ble_total']   = ble_total
                    self._cache['wifi_total']  = wifi_total
                    self._cache['wl_macs']     = wl_macs
                    self._cache['wl_entries']  = wl_entries
                    self._cache['version']    += 1

                # ── Vibration alerts ──────────────────────────────
                highest = None
                for d in all_devs:
                    mac = d['mac'].upper()
                    if mac in wl_macs:
                        continue
                    score = d.get('threat_score', 0.0)
                    if score >= 0.80:
                        lvl = 3  # critical
                    elif score >= 0.60:
                        lvl = 2  # high
                    elif score >= 0.40:
                        lvl = 1  # medium
                    else:
                        continue
                    prev = self._alerted.get(mac, 0)
                    if lvl > prev:
                        self._alerted[mac] = lvl
                        if highest is None or lvl > highest:
                            highest = lvl
                if highest is not None:
                    label = {3: 'critical', 2: 'high', 1: 'medium'}[highest]
                    with self._vib_lock:
                        self._vib_queue.append(label)

            except Exception:
                try:
                    if conn: conn.close()
                except Exception:
                    pass
                try:
                    if wl_conn: wl_conn.close()
                except Exception:
                    pass
                conn    = None
                wl_conn = None
            time.sleep(3)
        for c in (conn, wl_conn):
            if c:
                try: c.close()
                except Exception: pass

    def cleanup(self):
        try:
            self.gfx.led_all_off()
            self.gfx.clear(BLACK)
            self.gfx.flip()
            self.gfx.cleanup()
        except Exception:
            pass

    # ── Input ─────────────────────────────────────────────────────

    def poll(self):
        """Poll input queue — must call before get_input_event."""
        self.gfx.poll_input()

    def next_event(self):
        """Return next (button, event_type) or None."""
        ev = self.gfx.get_input_event()
        if ev:
            return ev[0], ev[1]
        return None

    def wait_press(self):
        """Block until a button PRESS. Returns button code."""
        while self.running:
            self.poll()
            ev = self.next_event()
            if ev and ev[1] == Pager.EVENT_PRESS:
                return ev[0]
            time.sleep(0.05)
        return None

    def drain_events(self):
        self.gfx.clear_input_events()

    # Vibration patterns per alert level
    _VIB_PATTERNS = {
        'critical': '300,100,300,100,300',  # 3 long pulses — someone is following you
        'high':     '200,100,200',           # 2 medium pulses
        'medium':   '150',                   # 1 short pulse
    }

    def _process_vibrations(self):
        """Called from UI loop — fire any queued vibration alerts."""
        with self._vib_lock:
            if not self._vib_queue:
                return
            # Play highest severity queued, discard the rest
            lvl_order = {'critical': 3, 'high': 2, 'medium': 1}
            best = max(self._vib_queue, key=lambda l: lvl_order.get(l, 0))
            self._vib_queue.clear()
        pattern = self._VIB_PATTERNS.get(best, '200')
        try:
            self.gfx.vibrate_pattern(pattern)
        except Exception:
            pass

    # ── Startup menu ──────────────────────────────────────────────

    def run_startup_menu(self):
        """
        Show title, daemon status, and options.
        Returns: 'start_gui' | 'exit' | 'stop'
        """
        # Build menu items dynamically
        def get_items():
            st = daemon_status()
            running = bool(st['ble'] or st['wifi'] or st['analyzer'])
            items = []
            if running:
                items.append(('start_gui', 'Open Device Monitor'))
            else:
                items.append(('start_gui', 'Start CYT + Open Monitor'))
            items.append(('web_toggle', None))   # drawn specially
            items.append(('whitelist', 'Manage Whitelist'))
            if running:
                items.append(('stop', 'Stop CYT'))
            items.append(('exit', 'Exit'))
            return items, st

        sel = 0
        web_on = bool(pid_alive(WEB_PID))
        self.drain_events()

        while self.running:
            items, st = get_items()
            sel = min(sel, len(items) - 1)

            # ── Draw ─────────────────────────────────────────────
            self.gfx.clear(BLACK)

            # Title bar
            self.gfx.fill_rect(0, 0, W, STATUS_H, NAVY)
            self._txt(4, 3, 'CHASING YOUR TAIL', WHITE)
            ver = 'v1.0'
            tw = self._tw(ver)
            self._txt(W - tw - 4, 3, ver, GRAY)

            # Daemon status line
            y = STATUS_H + 3
            dx = 4
            for label, pid in [('BLE', st['ble']), ('WiFi', st['wifi']),
                                ('GPS', st['gps']), ('Web', st['web']),
                                ('Ana', st['analyzer'])]:
                col = DKGREEN if pid else DARKGRAY
                self._txt(dx, y, label + ':', GRAY, FONT_SM)
                dx += self._tw(label + ': ', FONT_SM)
                self._txt(dx, y, 'ON ' if pid else 'OFF', col, FONT_SM)
                dx += self._tw('ON  ', FONT_SM) + 4

            # Device summary
            y2 = y + 20
            with self._cache_lock:
                devs = list(self._cache['all_devs'])
            n_total = len(devs)
            n_high  = sum(1 for d in devs if d['threat_score'] >= 0.60)
            n_med   = sum(1 for d in devs if 0.40 <= d['threat_score'] < 0.60)
            summary = f'{n_total} devices'
            if n_high:  summary += f'  {n_high} HIGH'
            if n_med:   summary += f'  {n_med} MED'
            if not devs: summary = 'No data yet'
            self._txt(4, y2, summary, CYAN, FONT_SM)

            # Separator
            sep_y = y2 + 20
            self.gfx.hline(0, sep_y, W, GRAY)

            # Menu items
            my = sep_y + 4
            for i, (action, label) in enumerate(items):
                is_sel = (i == sel)
                fg = GREEN if is_sel else WHITE
                prefix = '> ' if is_sel else '  '

                if action == 'web_toggle':
                    web_label = prefix + 'Web UI: '
                    self._txt(4, my, web_label, fg)
                    tw = self._tw(web_label)
                    val = 'ON' if web_on else 'OFF'
                    vcol = DKGREEN if web_on else RED
                    self._txt(4 + tw, my, val, vcol)
                else:
                    self._txt(4, my, prefix + label, fg)

                my += 22

            # Control bar
            cy = H - CTRL_H
            self.gfx.fill_rect(0, cy, W, CTRL_H, DARKGRAY)
            self.gfx.hline(0, cy, W, GRAY)
            self._txt(4, cy + 3, '[A] Select', WHITE, FONT_SM)

            self.gfx.flip()

            # ── Input ────────────────────────────────────────────
            self.poll()
            ev = self.next_event()
            if not ev:
                time.sleep(0.05)
                continue

            btn, etype = ev
            if etype != Pager.EVENT_PRESS:
                continue

            if btn == Pager.BTN_UP:
                sel = (sel - 1) % len(items)
            elif btn == Pager.BTN_DOWN:
                sel = (sel + 1) % len(items)
            elif btn == Pager.BTN_A:
                action = items[sel][0]
                if action == 'start_gui':
                    return 'start_gui', web_on
                elif action == 'web_toggle':
                    web_on = not web_on
                    if web_on and not pid_alive(WEB_PID):
                        self._start_web()
                    elif not web_on and pid_alive(WEB_PID):
                        kill_daemon(WEB_PID)
                elif action == 'whitelist':
                    self.run_whitelist_screen()
                    self.drain_events()
                elif action == 'stop':
                    return 'stop', web_on
                elif action == 'exit':
                    return 'exit', web_on

        return 'exit', False

    def _start_web(self):
        python = '/mmc/usr/bin/python3'
        subprocess.Popen([python, os.path.join(PAYLOAD_DIR, 'web_server.py'),
                          '--db', self.db_path, '--status', STATUS_JSON,
                          '--port', '8080', '--daemon', '--pidfile', WEB_PID])

    # ── Device list ───────────────────────────────────────────────

    def _draw_status_bar(self, ble_total, wifi_total, threats, filter_src):
        self.gfx.fill_rect(0, 0, W, STATUS_H, NAVY)
        ts = time.strftime('%I:%M%p').lstrip('0')
        self._txt(2, 3, f'CYT  B:{ble_total} W:{wifi_total}', WHITE, FONT_SM)
        right = f'{filter_src.upper()}  {ts}'
        if threats > 0:
            right = f'!{threats}  ' + right
        tw = self._tw(right, FONT_SM)
        self._txt(W - tw - 2, 3, right, RED if threats > 0 else GRAY, FONT_SM)

    def _draw_ctrl_bar(self):
        y = H - CTRL_H
        self.gfx.fill_rect(0, y, W, CTRL_H, DARKGRAY)
        self.gfx.hline(0, y, W, GRAY)
        self._txt(4, y + 3, '[A] Detail  [B] Menu  [<>] Filter', WHITE, FONT_SM)

    def _draw_device_row(self, idx, d, selected):
        y  = LIST_Y + idx * ROW_H
        bg = DARKGRAY if selected else BLACK
        fg = threat_color(d['threat_score'])
        self.gfx.fill_rect(0, y, W, ROW_H, bg)

        gap = self._tw('  ', FONT_SM)

        x = 2
        if d.get('whitelisted'):
            score_str = 'WL'
            fg        = DKGREEN
        else:
            fg        = threat_color(d['threat_score'])
            score_str = f'{threat_label(d["threat_score"])} {d["threat_score"]:.2f}'
        self._txt(x, y + 3, score_str, fg, FONT_SM)
        x += self._tw(score_str, FONT_SM) + gap

        self._txt(x, y + 3, d['mac'], WHITE if selected else GRAY, FONT_SM)
        x += self._tw(d['mac'], FONT_SM) + gap

        src = d['source']
        if src == 'ble':     src_col = CYAN
        elif src == 'drone': src_col = ORANGE
        elif src == 'wifi':  src_col = GREEN
        else:                src_col = GRAY
        src_label = src.upper() if src != '?' else '--'
        if d.get('cluster_id'): src_label += f' C{d["cluster_id"]}'
        if d.get('group_id'):   src_label += f' G{d["group_id"]}'
        self._txt(x, y + 3, src_label, src_col, FONT_SM)
        x += self._tw(src_label, FONT_SM) + gap

        # Right-side info — name/SSIDs first, fall back to manufacturer
        if d['source'] == 'wifi':
            ssid_set = d.get('ssid_set') or ''
            info = ssid_set.replace(',', '  ').strip() or \
                   (d.get('name') or d.get('manufacturer') or '').strip()
        else:
            info = (d.get('name') or d.get('manufacturer') or '').strip()
        if info and x < W - 20:
            info = self._fit(info, W - x - 4, FONT_SM)
            if info:
                self._txt(x, y + 3, info, CYAN, FONT_SM)

    def _show_detail(self, d):
        import datetime as dt

        def lvl(s):
            if s >= 0.80: return 'CRITICAL'
            if s >= 0.60: return 'HIGH'
            if s >= 0.40: return 'MEDIUM'
            if s >= 0.20: return 'LOW'
            return 'NORMAL'

        def draw(is_wl, msg=''):
            self.gfx.clear(BLACK)
            fg = threat_color(d['threat_score'])
            y  = 4

            self._txt(4, y, 'Device Detail', WHITE); y += 22
            self.gfx.hline(0, y, W, GRAY); y += 6

            mfr = (d.get('manufacturer') or d.get('name') or 'Unknown')[:24]
            lines = [
                (f'MAC: {d["mac"]}', WHITE),
                (f'{d["source"].upper()}  Score: {d["threat_score"]:.2f}  [{lvl(d["threat_score"])}]', fg),
                (f'RSSI: {d["avg_rssi"]}dBm  Seen: {d["sighting_count"]}x', WHITE),
            ]
            if d.get('first_seen'):
                first = dt.datetime.fromtimestamp(d['first_seen']).strftime('%I:%M%p').lstrip('0')
                last  = dt.datetime.fromtimestamp(d['last_seen']).strftime('%I:%M%p').lstrip('0')
                dur   = int((d['last_seen'] - d['first_seen']) / 60)
                lines.append((f'{first} - {last}  {dur}min', WHITE))
            lines.append((f'Mfr: {mfr}', CYAN))
            if d.get('source') == 'wifi' and d.get('ssid_set'):
                probes = d['ssid_set'].replace(',', '  ')
                lines.append((f'Probes: {probes}', CYAN))
            if d.get('locations_seen', 0) > 1:
                lines.append((f'MULTI-LOC: {d["locations_seen"]} positions', RED))
            if d.get('cluster_id'):
                lines.append((f'Cluster C{d["cluster_id"]} (MAC rotating)', YELLOW))
            if d.get('group_id'):
                lines.append((f'Group G{d["group_id"]} (co-traveling)', ORANGE))
            if is_wl:
                lines.append(('[ WHITELISTED ]', DKGREEN))

            clip = H - CTRL_H - 4
            for text, color in lines:
                if y + FONT_MD > clip:
                    break
                self._txt(4, y, text, color)
                y += FONT_MD + 4

            if msg:
                self._txt(4, H - CTRL_H - FONT_MD - 4, msg, GREEN)

            cy = H - CTRL_H
            self.gfx.hline(0, cy - 1, W, GRAY)
            self.gfx.fill_rect(0, cy, W, CTRL_H, DARKGRAY)
            wl_label = '[<] Un-WL' if is_wl else '[<] Whitelist'
            self._txt(4, cy + 3, f'[A/B] Back  {wl_label}', WHITE, FONT_SM)
            self.gfx.flip()

        # Check current whitelist status using a short-lived connection
        try:
            wconn  = dbmod.open_whitelist_db(self.wl_path)
            is_wl  = dbmod.is_whitelisted(wconn, d['mac'])
        except Exception:
            wconn  = None
            is_wl  = False

        draw(is_wl)
        self.drain_events()

        while self.running:
            self.poll()
            ev = self.next_event()
            if not ev:
                time.sleep(0.05)
                continue
            btn, etype = ev
            if etype != Pager.EVENT_PRESS:
                continue
            if btn in (Pager.BTN_A, Pager.BTN_B):
                break
            if btn == Pager.BTN_LEFT:
                try:
                    if wconn is None:
                        wconn = dbmod.open_whitelist_db(self.wl_path)
                    if is_wl:
                        dbmod.remove_from_whitelist(wconn, d['mac'])
                        is_wl = False
                        msg   = 'Removed from whitelist'
                    else:
                        name = d.get('manufacturer') or d.get('name') or ''
                        dbmod.add_to_whitelist(wconn, d['mac'], name)
                        is_wl = True
                        msg   = 'Added to whitelist'
                except Exception as e:
                    msg = f'Error: {e}'
                draw(is_wl, msg)
                self.drain_events()

        if wconn:
            try: wconn.close()
            except Exception: pass

    def run_device_list(self):
        """
        Returns: 'menu' | 'exit_keep' | 'exit_stop' | 'exit_stop_web'
        """
        FILTER_CYCLE = ['all', 'ble', 'wifi', 'drone', 'whitelist']
        scroll      = 0
        sel         = 0
        filter_idx  = 0
        prev_max    = 0.0
        devices     = []
        ble_total   = 0
        wifi_total  = 0
        max_score   = 0.0
        threats     = 0
        last_version = -1
        last_time    = ''
        need_redraw  = True

        self.drain_events()

        while self.running:
            cur_filter = FILTER_CYCLE[filter_idx]

            # ── Vibration alerts ──────────────────────────────────
            self._process_vibrations()

            # ── Input first — always responsive ───────────────────
            self.poll()
            ev = self.next_event()
            if ev:
                btn, etype = ev
                if etype == Pager.EVENT_PRESS:
                    if btn == Pager.BTN_DOWN:
                        sel = min(sel + 1, max(0, len(devices) - 1))
                        if sel >= scroll + ROWS_VIS:
                            scroll = sel - ROWS_VIS + 1
                        need_redraw = True
                    elif btn == Pager.BTN_UP:
                        sel = max(sel - 1, 0)
                        if sel < scroll:
                            scroll = sel
                        need_redraw = True
                    elif btn == Pager.BTN_A:
                        if devices and sel < len(devices):
                            self._show_detail(devices[sel])
                            self.drain_events()
                            need_redraw = True
                    elif btn in (Pager.BTN_LEFT, Pager.BTN_RIGHT):
                        filter_idx  = (filter_idx + 1) % len(FILTER_CYCLE)
                        scroll      = 0
                        sel         = 0
                        last_version = -1   # force recompute for new filter
                        need_redraw = True
                    elif btn == Pager.BTN_B:
                        result = self.run_exit_menu()
                        if result != 'back':
                            return result
                        self.drain_events()
                        need_redraw = True
                continue   # process all queued events before drawing

            # ── Check for new data ────────────────────────────────
            with self._cache_lock:
                cur_version = self._cache['version']
                if cur_version != last_version:
                    all_devs   = list(self._cache['all_devs'])
                    ble_total  = self._cache['ble_total']
                    wifi_total = self._cache['wifi_total']
                    wl_macs    = self._cache['wl_macs']
                    wl_entries = list(self._cache['wl_entries'])
                    last_version = cur_version

                    if cur_filter == 'whitelist':
                        # Build list of whitelisted devices — from persistence + stubs for unseen
                        covered = {d['mac'].upper(): dict(d, whitelisted=True)
                                   for d in all_devs if d['mac'].upper() in wl_macs}
                        for e in wl_entries:
                            m = e['mac'].upper()
                            if m not in covered:
                                covered[m] = {
                                    'mac': e['mac'], 'source': '?', 'threat_score': 0.0,
                                    'manufacturer': e.get('name', ''), 'name': '',
                                    'avg_rssi': 0, 'sighting_count': 0,
                                    'first_seen': None, 'last_seen': None,
                                    'locations_seen': 0, 'cluster_id': None,
                                    'group_id': None, 'whitelisted': True,
                                }
                        devices = list(covered.values())[:self.limit]
                        threats = 0
                    else:
                        devices = [d for d in all_devs
                                   if d['mac'].upper() not in wl_macs
                                   and (cur_filter == 'all' or d['source'] == cur_filter)
                                   ][:self.limit]
                        threats = sum(1 for d in devices if d['threat_score'] >= 0.40)

                    max_score = max((d['threat_score'] for d in devices), default=0.0)
                    sel       = min(sel, max(0, len(devices) - 1))
                    need_redraw = True

            # Check for time change (status bar HH:MM)
            cur_time = time.strftime('%I:%M%p').lstrip('0')
            if cur_time != last_time:
                last_time   = cur_time
                need_redraw = True

            # ── LED alerts ────────────────────────────────────────
            if max_score != prev_max:
                self._update_leds(max_score)
                prev_max = max_score

            # ── Draw only when something changed ──────────────────
            if need_redraw:
                self.gfx.clear(BLACK)
                self._draw_status_bar(ble_total, wifi_total, threats, cur_filter)
                self.gfx.hline(0, STATUS_H, W, GRAY)
                for i in range(ROWS_VIS):
                    idx = scroll + i
                    if idx >= len(devices):
                        break
                    self._draw_device_row(i, devices[idx], selected=(idx == sel))
                self._draw_ctrl_bar()
                self.gfx.flip()
                need_redraw = False
            else:
                time.sleep(0.05)

        return 'exit_keep'

    def _update_leds(self, max_score):
        try:
            if max_score >= 0.80:
                for b in ('up', 'down', 'left', 'right'):
                    self.gfx.led_rgb(b, 255, 0, 0)
                self.gfx.led_set('a-button-led', 255)
                self.gfx.led_set('b-button-led', 255)
            elif max_score >= 0.60:
                for b in ('up', 'down', 'left', 'right'):
                    self.gfx.led_rgb(b, 255, 100, 0)
                self.gfx.led_set('a-button-led', 180)
                self.gfx.led_set('b-button-led', 0)
            elif max_score >= 0.40:
                for b in ('up', 'down', 'left', 'right'):
                    self.gfx.led_rgb(b, 180, 180, 0)
                self.gfx.led_set('a-button-led', 0)
                self.gfx.led_set('b-button-led', 0)
            else:
                self.gfx.led_all_off()
        except Exception:
            pass

    # ── Whitelist screen ──────────────────────────────────────────

    def run_whitelist_screen(self):
        """Show whitelisted devices. A = remove selected. B = back."""
        sel = 0
        msg = ''
        msg_timer = 0

        self.drain_events()

        while self.running:
            with self._cache_lock:
                entries = list(self._cache['wl_entries'])

            # ── Input first ───────────────────────────────────────
            self.poll()
            ev = self.next_event()
            if ev:
                btn, etype = ev
                if etype == Pager.EVENT_PRESS:
                    if btn == Pager.BTN_UP:
                        sel = max(sel - 1, 0)
                    elif btn == Pager.BTN_DOWN:
                        sel = min(sel + 1, max(0, len(entries) - 1))
                    elif btn == Pager.BTN_A and entries:
                        mac = entries[sel]['mac']
                        try:
                            wconn = dbmod.open_whitelist_db(self.wl_path)
                            dbmod.remove_from_whitelist(wconn, mac)
                            wconn.close()
                            msg = f'Removed {mac}'
                        except Exception as e:
                            msg = f'Error: {e}'
                        msg_timer = time.time() + 2
                        sel = max(0, sel - 1) if sel >= len(entries) - 1 else sel
                    elif btn in (Pager.BTN_B, Pager.BTN_LEFT):
                        return
                continue

            # ── Draw ─────────────────────────────────────────────
            self.gfx.clear(BLACK)
            self.gfx.fill_rect(0, 0, W, STATUS_H, NAVY)
            self._txt(4, 3, 'WHITELIST', WHITE)
            n = len(entries)
            self._txt(W - self._tw(f'{n} entries') - 4, 3, f'{n} entries', GRAY)

            y = STATUS_H + 4
            row_h = FONT_SM + 6
            if not entries:
                self._txt(4, y + 20, 'Whitelist is empty.', GRAY)
            else:
                visible = (H - STATUS_H - CTRL_H - 4) // row_h
                start   = max(0, sel - visible + 1) if sel >= visible else 0
                for i, e in enumerate(entries[start:start + visible]):
                    row_i = start + i
                    is_sel = (row_i == sel)
                    bg = DARKGRAY if is_sel else BLACK
                    self.gfx.fill_rect(0, y, W, row_h - 1, bg)
                    prefix = '> ' if is_sel else '  '
                    name = e.get('name') or ''
                    label = f'{prefix}{e["mac"]}'
                    if name:
                        label += f'  {name[:16]}'
                    self._txt(4, y + 2, label, WHITE if is_sel else GRAY, FONT_SM)
                    y += row_h

            if msg and time.time() < msg_timer:
                self._txt(4, H - CTRL_H - FONT_SM - 4, msg, GREEN, FONT_SM)

            cy = H - CTRL_H
            self.gfx.fill_rect(0, cy, W, CTRL_H, DARKGRAY)
            self.gfx.hline(0, cy, W, GRAY)
            self._txt(4, cy + 3, '[A] Remove  [B] Back', WHITE, FONT_SM)
            self.gfx.flip()
            time.sleep(0.05)

    # ── Exit menu ─────────────────────────────────────────────────

    def run_exit_menu(self):
        """
        Returns: 'exit_keep' | 'exit_stop' | 'exit_stop_web' | 'back'
        """
        items = [
            ('back',          'Back to device list'),
            ('menu',          'Back to start menu'),
            ('exit_keep',     'Keep running (exit UI)'),
            ('exit_stop_web', 'Stop web UI only'),
            ('exit_stop',     'Stop CYT completely'),
        ]
        sel = 0
        self.drain_events()

        while self.running:
            self.gfx.clear(BLACK)

            # Header
            self.gfx.fill_rect(0, 0, W, STATUS_H, NAVY)
            self._txt(4, 3, 'Exit CYT?', WHITE)

            # Items
            my = STATUS_H + 10
            for i, (action, label) in enumerate(items):
                is_sel = (i == sel)
                fg     = GREEN if is_sel else WHITE
                prefix = '> ' if is_sel else '  '
                self._txt(4, my, prefix + label, fg)
                my += FONT_MD + 6

            # Control bar
            cy = H - CTRL_H
            self.gfx.fill_rect(0, cy, W, CTRL_H, DARKGRAY)
            self.gfx.hline(0, cy, W, GRAY)
            self._txt(4, cy + 4, '[A] Select  [B] Back', WHITE, FONT_SM)

            self.gfx.flip()

            self.poll()
            ev = self.next_event()
            if not ev:
                time.sleep(0.05)
                continue

            btn, etype = ev
            if etype != Pager.EVENT_PRESS:
                continue

            if btn == Pager.BTN_UP:
                sel = (sel - 1) % len(items)
            elif btn == Pager.BTN_DOWN:
                sel = (sel + 1) % len(items)
            elif btn == Pager.BTN_A:
                return items[sel][0]
            elif btn == Pager.BTN_B:
                return 'back'

        return 'back'

    # ── Main ──────────────────────────────────────────────────────

    def run(self):
        try:
            while self.running:
                action, web_on = self.run_startup_menu()

                if action == 'stop':
                    self._show_message('Stopping CYT...')
                    stop_all()
                    time.sleep(1)
                    return 0

                if action == 'exit':
                    return 0

                # 'start_gui'
                if not cyt_running():
                    self._show_message('Starting CYT...')
                    start_daemons(with_web=web_on, db_path=self.db_path)
                elif web_on and not pid_alive(WEB_PID):
                    self._start_web()
                elif not web_on and pid_alive(WEB_PID):
                    kill_daemon(WEB_PID)

                self.drain_events()
                result = self.run_device_list()

                if result == 'exit_keep':
                    return 0
                elif result == 'exit_stop':
                    self._show_message('Stopping CYT...')
                    stop_all()
                    time.sleep(1)
                    return 1
                elif result == 'exit_stop_web':
                    kill_daemon(WEB_PID)
                    # loop back to startup menu
                    continue
                # any other result: loop back to startup menu

        finally:
            self.cleanup()

        return 0

    def _show_message(self, msg):
        self.gfx.clear(BLACK)
        tw = self._tw(msg)
        self._txt((W - tw) // 2, H // 2 - FONT_MD // 2, msg, WHITE)
        self.gfx.flip()


# ── Entry point ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='CYT Unified GUI')
    parser.add_argument('--db',    required=True, help='SQLite database path')
    parser.add_argument('--limit', type=int, default=20, help='Max devices shown')
    args = parser.parse_args()

    app = CYTApp(args.db, args.limit)
    sys.exit(app.run())


if __name__ == '__main__':
    main()
