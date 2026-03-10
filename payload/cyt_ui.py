#!/mmc/usr/bin/python3
"""
cyt_ui.py — Display UI for Chasing Your Tail

GUI mode (with pagerctl):  Full 480x222 display, LED alerts, buzzer.
Headless mode (no pagerctl): ANSI terminal output, auto-refreshes.

Usage:
    cyt_ui.py --db PATH [--filter all|ble|wifi] [--refresh N] [--limit N]
"""
import argparse
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import db as dbmod

# ── Try importing pagerctl ──────────────────────────────────────────
HAVE_PAGERCTL = False
pager = None

def _try_init_pagerctl():
    global HAVE_PAGERCTL, pager
    lib_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib')
    sys.path.insert(0, lib_dir)
    try:
        from pagerctl import Pager
        pager = Pager()
        pager.init()
        pager.set_rotation(270)   # Landscape: 480 wide × 222 tall
        HAVE_PAGERCTL = True
        return True
    except Exception as e:
        print(f'[ui] pagerctl not available ({e}), running in terminal mode', flush=True)
        return False

# ── Layout constants ────────────────────────────────────────────────
W, H        = 480, 222
STATUS_H    = 20
CTRL_H      = 18
ROW_H       = 20
LIST_Y      = STATUS_H + 1
LIST_H      = H - STATUS_H - CTRL_H - 2
ROWS_VIS    = LIST_H // ROW_H   # ~9 rows

# ── RGB565 colors ───────────────────────────────────────────────────
BLACK     = 0x0000
WHITE     = 0xFFFF
RED       = 0xF800
ORANGE    = 0xFD20
YELLOW    = 0xFFE0
GREEN     = 0x07E0
DARKGREEN = 0x03E0
CYAN      = 0x07FF
BLUE      = 0x001F
GRAY      = 0x8410
DARKGRAY  = 0x2104
NAVY      = 0x000F

running = True


def sig_handler(sig, frame):
    global running
    running = False


def threat_color_rgb565(score: float) -> int:
    if score >= 0.80: return RED
    if score >= 0.60: return ORANGE
    if score >= 0.40: return YELLOW
    if score >= 0.20: return GREEN
    return GRAY


def threat_label(score: float) -> str:
    if score >= 0.80: return 'CRIT'
    if score >= 0.60: return 'HIGH'
    if score >= 0.40: return ' MED'
    if score >= 0.20: return ' LOW'
    return '  OK'


def threat_ansi(score: float) -> str:
    """ANSI color escape for terminal mode."""
    if score >= 0.80: return '\033[1;31m'   # bold red
    if score >= 0.60: return '\033[1;33m'   # bold yellow
    if score >= 0.40: return '\033[1;35m'   # bold magenta
    if score >= 0.20: return '\033[0;32m'   # green
    return '\033[0;90m'                      # dark gray


# ════════════════════════════════════════════════════════════════════
#  Terminal / headless mode
# ════════════════════════════════════════════════════════════════════

def terminal_display(devices: list, ble_total: int, wifi_total: int,
                      filter_src: str) -> None:
    threats = sum(1 for d in devices if d['threat_score'] >= 0.40)
    ts = time.strftime('%H:%M:%S')
    print('\033[2J\033[H', end='')   # clear + home
    print(f'\033[1;37;44m CYT  BLE:{ble_total:<4d} WiFi:{wifi_total:<4d}'
          f'  Filter:{filter_src:<5}  Threats:{threats:<3d}  {ts} \033[0m')
    print(f"{'LVL':4s} {'MAC':17s} {'SRC':5s} {'SCORE':5s} {'RSSI':5s} "
          f"{'SEEN':4s}  {'MANUFACTURER':28s}  NAME")
    print('─' * 90)

    for d in devices:
        color = threat_ansi(d['threat_score'])
        lbl   = threat_label(d['threat_score'])
        mfr   = (d.get('manufacturer') or 'Unknown')[:28]
        nm    = (d.get('name') or '')[:22]
        print(f"{color}{lbl}  {d['mac']}  {d['source']:<5s} "
              f"{d['threat_score']:5.2f} {d['avg_rssi']:5d} "
              f"{d['sighting_count']:4d}  {mfr:<28s}  {nm}\033[0m")

    print(f'\n\033[2;37m[Ctrl+C] Exit  [auto-refresh]\033[0m', flush=True)


# ════════════════════════════════════════════════════════════════════
#  pagerctl GUI mode
# ════════════════════════════════════════════════════════════════════

def draw_status_bar(ble_total: int, wifi_total: int,
                     threat_count: int, filter_src: str) -> None:
    pager.fill_rect(0, 0, W, STATUS_H, NAVY)
    ts = time.strftime('%H:%M')
    pager.draw_text(2, 3, f'CYT  BLE:{ble_total} WiFi:{wifi_total}', WHITE, 1)
    if threat_count > 0:
        pager.draw_text(240, 3, f'! {threat_count} THREATS !', RED, 1)
    # right-align filter + time
    right = f'{filter_src.upper()}  {ts}'
    tw = pager.text_width(right, 1)
    pager.draw_text(W - tw - 4, 3, right, GRAY, 1)


def draw_ctrl_bar(filter_src: str) -> None:
    y = H - CTRL_H
    pager.fill_rect(0, y, W, CTRL_H, DARKGRAY)
    pager.hline(0, y, W, GRAY)
    pager.draw_text(4, y + 3, '[A]Detail [B]Exit [</]Filter [^v]Scroll', WHITE, 1)


def draw_device_row(idx: int, d: dict, selected: bool) -> None:
    y = LIST_Y + idx * ROW_H
    bg = DARKGRAY if selected else BLACK
    fg = threat_color_rgb565(d['threat_score'])

    pager.fill_rect(0, y, W, ROW_H, bg)

    # Left threat bar (4px wide)
    bar_h = max(2, int(d['threat_score'] * ROW_H))
    pager.fill_rect(0, y + (ROW_H - bar_h), 4, bar_h, fg)

    # Score + label
    lbl = threat_label(d['threat_score'])
    pager.draw_text(6, y + 3, f'{lbl} {d["threat_score"]:.2f}', fg, 1)

    # MAC
    pager.draw_text(78, y + 3, d['mac'], WHITE if selected else GRAY, 1)

    # Source tag
    src_color = CYAN if d['source'] == 'ble' else GREEN
    pager.draw_text(209, y + 3, d['source'].upper(), src_color, 1)

    # Manufacturer + name (truncate to fit)
    mfr = (d.get('manufacturer') or 'Unknown')
    nm  = (d.get('name') or '')
    label = f'{mfr[:22]}  {nm[:18]}'.rstrip()
    pager.draw_text(240, y + 3, label, fg, 1)

    # RSSI on far right
    rssi_str = f'{d["avg_rssi"]}dB'
    tw = pager.text_width(rssi_str, 1)
    pager.draw_text(W - tw - 4, y + 3, rssi_str, GRAY, 1)


def show_detail(d: dict) -> None:
    """Full-screen device detail view. Wait for any button to go back."""
    pager.clear(BLACK)
    y = 4
    fg = threat_color_rgb565(d['threat_score'])
    def threat_level(score):
        if score >= 0.80: return 'CRITICAL'
        if score >= 0.60: return 'HIGH'
        if score >= 0.40: return 'MEDIUM'
        if score >= 0.20: return 'LOW'
        return 'NORMAL'

    pager.draw_text(4, y, 'Device Detail', WHITE, 2); y += 22
    pager.hline(0, y, W, GRAY); y += 6

    lines = [
        (f'MAC:    {d["mac"]}  ({d["source"].upper()})', WHITE),
        (f'Score:  {d["threat_score"]:.2f}  [{threat_level(d["threat_score"])}]', fg),
        (f'Device: {d.get("manufacturer") or "Unknown"}', CYAN),
        (f'Name:   {d.get("name") or "(none)"}', CYAN),
        (f'RSSI:   {d["avg_rssi"]} dBm', WHITE),
        (f'Seen:   {d["sighting_count"]} times', WHITE),
    ]
    if d['first_seen']:
        first = time.strftime('%H:%M:%S', time.localtime(d['first_seen']))
        last  = time.strftime('%H:%M:%S', time.localtime(d['last_seen']))
        dur   = int((d['last_seen'] - d['first_seen']) / 60)
        lines += [
            (f'First:  {first}', WHITE),
            (f'Last:   {last}', WHITE),
            (f'Duration: {dur} min', WHITE),
        ]
    if d.get('locations_seen', 0) > 1:
        lines.append((f'*** MULTI-LOCATION: {d["locations_seen"]} positions ***', RED))

    for text, color in lines:
        pager.draw_text(4, y, text, color, 1)
        y += 14

    y = H - CTRL_H
    pager.hline(0, y - 1, W, GRAY)
    pager.fill_rect(0, y, W, CTRL_H, DARKGRAY)
    pager.draw_text(4, y + 3, '[A/B] Back', WHITE, 1)
    pager.flip()

    # Wait for any button press to dismiss
    pager.clear_input_events()
    while running:
        ev = pager.get_input_event()
        if ev and ev[1] == pager.EVENT_PRESS:
            break
        time.sleep(0.05)


def update_leds(max_score: float, prev_score: float) -> None:
    if max_score >= 0.80:
        for btn in ('up', 'down', 'left', 'right'):
            pager.led_rgb(btn, 255, 0, 0)
        pager.led_set('a-button-led', 255)
        pager.led_set('b-button-led', 255)
        if max_score > prev_score:
            pager.play_rtttl('alert:d=8,o=5,b=200:c6,p,c6,p,c6', 0)
    elif max_score >= 0.60:
        for btn in ('up', 'down', 'left', 'right'):
            pager.led_rgb(btn, 255, 100, 0)
        pager.led_set('a-button-led', 180)
        pager.led_set('b-button-led', 0)
        if max_score > prev_score:
            pager.beep(600, 80)
    elif max_score >= 0.40:
        for btn in ('up', 'down', 'left', 'right'):
            pager.led_rgb(btn, 180, 180, 0)
        pager.led_set('a-button-led', 0)
        pager.led_set('b-button-led', 0)
    else:
        pager.led_all_off()


# ════════════════════════════════════════════════════════════════════
#  Main UI loop
# ════════════════════════════════════════════════════════════════════

FILTER_CYCLE = ['all', 'ble', 'wifi']


def run_ui(conn, filter_src: str, refresh_sec: int, limit: int) -> None:
    global running
    scroll     = 0
    sel        = 0
    prev_max   = 0.0
    filter_idx = FILTER_CYCLE.index(filter_src) if filter_src in FILTER_CYCLE else 0

    # Cached data — refreshed every refresh_sec, not every frame
    devices    = []
    ble_total  = 0
    wifi_total = 0
    max_score  = 0.0
    threats    = 0
    last_fetch = 0.0
    force_fetch = True

    while running:
        now        = time.time()
        cur_filter = FILTER_CYCLE[filter_idx]

        if HAVE_PAGERCTL:
            # ── Input: drain event queue (never misses a press) ─────
            ev = pager.get_input_event()
            while ev:
                button, event_type, _ = ev
                if event_type == pager.EVENT_PRESS:
                    if button == pager.BTN_DOWN:
                        sel = min(sel + 1, max(0, len(devices) - 1))
                        if sel >= scroll + ROWS_VIS:
                            scroll = sel - ROWS_VIS + 1
                    elif button == pager.BTN_UP:
                        sel = max(sel - 1, 0)
                        if sel < scroll:
                            scroll = sel
                    elif button == pager.BTN_B:
                        running = False
                        break
                    elif button == pager.BTN_A:
                        if devices and sel < len(devices):
                            show_detail(devices[sel])
                            pager.clear_input_events()
                    elif button in (pager.BTN_LEFT, pager.BTN_RIGHT):
                        filter_idx  = (filter_idx + 1) % len(FILTER_CYCLE)
                        cur_filter  = FILTER_CYCLE[filter_idx]
                        scroll      = 0
                        sel         = 0
                        force_fetch = True
                ev = pager.get_input_event()

            if not running:
                break

            # ── Data refresh (only every refresh_sec, not per frame) ─
            if force_fetch or now - last_fetch >= refresh_sec:
                try:
                    all_devs   = dbmod.query_persistence(conn, limit=limit * 2)
                    devices    = [d for d in all_devs
                                  if cur_filter == 'all' or d['source'] == cur_filter][:limit]
                    max_score  = max((d['threat_score'] for d in devices), default=0.0)
                    threats    = sum(1 for d in devices if d['threat_score'] >= 0.40)
                    ble_total  = dbmod.count_unique_macs(conn, 3600, 'ble')
                    wifi_total = dbmod.count_unique_macs(conn, 3600, 'wifi')
                    sel        = min(sel, max(0, len(devices) - 1))
                    last_fetch  = time.time()
                    force_fetch = False
                except Exception:
                    pass

            # ── Draw ─────────────────────────────────────────────────
            pager.clear(BLACK)
            draw_status_bar(ble_total, wifi_total, threats, cur_filter)
            pager.hline(0, STATUS_H, W, GRAY)

            for i in range(ROWS_VIS):
                idx = scroll + i
                if idx >= len(devices):
                    break
                draw_device_row(i, devices[idx], selected=(idx == sel))

            draw_ctrl_bar(cur_filter)
            pager.flip()

            # ── LED alerts ───────────────────────────────────────────
            if max_score != prev_max:
                update_leds(max_score, prev_max)
                prev_max = max_score

            time.sleep(0.08)   # ~12 FPS

        else:
            # Terminal mode — fetch + redraw every refresh_sec
            if now - last_fetch >= refresh_sec:
                try:
                    all_devs   = dbmod.query_persistence(conn, limit=limit * 2)
                    devices    = [d for d in all_devs
                                  if cur_filter == 'all' or d['source'] == cur_filter][:limit]
                    ble_total  = dbmod.count_unique_macs(conn, 3600, 'ble')
                    wifi_total = dbmod.count_unique_macs(conn, 3600, 'wifi')
                    last_fetch = time.time()
                except Exception:
                    pass
                terminal_display(devices, ble_total, wifi_total, cur_filter)
            time.sleep(0.5)

    if HAVE_PAGERCTL:
        pager.led_all_off()
        pager.clear(BLACK)
        pager.draw_text_centered(H // 2 - 8, 'CYT stopped.', WHITE, 2)
        pager.flip()
        time.sleep(1)
        pager.cleanup()


# ════════════════════════════════════════════════════════════════════
#  Entry point
# ════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='CYT Display UI')
    parser.add_argument('--db',      required=True, help='SQLite database path')
    parser.add_argument('--filter',  default='all', choices=['all', 'ble', 'wifi'])
    parser.add_argument('--refresh', type=int, default=3,  help='Terminal refresh interval')
    parser.add_argument('--limit',   type=int, default=20, help='Max devices shown')
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT,  sig_handler)

    _try_init_pagerctl()

    conn = dbmod.open_db(args.db)

    try:
        run_ui(conn, args.filter, args.refresh, args.limit)
    finally:
        conn.close()


if __name__ == '__main__':
    main()
