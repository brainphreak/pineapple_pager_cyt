#!/mmc/usr/bin/python3
"""
gps.py — Background GPS reader for Chasing Your Tail
Connects to gpsd on localhost:2947 and maintains a current fix.
Thread-safe. Falls back to (0.0, 0.0) when no fix available.

Usage:
    import gps as gpsmod
    gpsmod.start()            # call once at startup
    lat, lon = gpsmod.get_location()
"""
import json
import socket
import threading
import time

_lat   = 0.0
_lon   = 0.0
_fix   = False
_lock  = threading.Lock()
_thread = None

GPSD_HOST = 'localhost'
GPSD_PORT = 2947


def get_location() -> tuple:
    """Return (lat, lon). Returns (0.0, 0.0) when no fix."""
    with _lock:
        return (_lat, _lon)


def has_fix() -> bool:
    with _lock:
        return _fix


def _reader():
    global _lat, _lon, _fix
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((GPSD_HOST, GPSD_PORT))
            sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
            buf = ''
            while True:
                try:
                    data = sock.recv(4096).decode('ascii', errors='replace')
                except socket.timeout:
                    continue
                if not data:
                    break
                buf += data
                while '\n' in buf:
                    line, buf = buf.split('\n', 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line)
                        if msg.get('class') == 'TPV':
                            mode = msg.get('mode', 0)
                            lat  = msg.get('lat', 0.0)
                            lon  = msg.get('lon', 0.0)
                            with _lock:
                                if mode >= 2 and lat and lon:
                                    _lat = lat
                                    _lon = lon
                                    _fix = True
                                else:
                                    _fix = False
                    except (ValueError, KeyError):
                        pass
        except Exception:
            with _lock:
                _fix = False
            time.sleep(5)   # retry after connection failure
        finally:
            try:
                sock.close()
            except Exception:
                pass


def start():
    """Start the background GPS reader thread (idempotent)."""
    global _thread
    if _thread and _thread.is_alive():
        return
    _thread = threading.Thread(target=_reader, daemon=True, name='gps-reader')
    _thread.start()
