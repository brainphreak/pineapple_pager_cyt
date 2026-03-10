#!/bin/sh
# Title: Chasing Your Tail
# Description: Passive surveillance detection - BLE/WiFi/Drone device tracking
# Author: brAinphreAk
# Version: 1.0
# Category: Reconnaissance
# Library: libpagerctl.so (pagerctl)

PAYLOAD_DIR="/mmc/root/payloads/reconnaissance/cyt"
DB="$PAYLOAD_DIR/cyt.db"
CYT_LOG="$PAYLOAD_DIR/cyt.log"
STATUS_JSON="$PAYLOAD_DIR/status.json"

BLE_PID="$PAYLOAD_DIR/ble.pid"
ANA_PID="$PAYLOAD_DIR/analyzer.pid"
WIFI_PID="$PAYLOAD_DIR/wifi.pid"
WEB_PID="$PAYLOAD_DIR/web.pid"

cd "$PAYLOAD_DIR" || { LOG "red" "ERROR: $PAYLOAD_DIR not found"; exit 1; }

# ── pagerctl ──────────────────────────────────────────────────────
PAGERCTL_FOUND=false
for dir in "$PAYLOAD_DIR/lib" "/mmc/root/payloads/reconnaissance/pagergotchi/lib" \
           "/mmc/root/payloads/utilities/PAGERCTL"; do
    if [ -f "$dir/libpagerctl.so" ] && [ -f "$dir/pagerctl.py" ]; then
        PAGERCTL_DIR="$dir"
        PAGERCTL_FOUND=true
        break
    fi
done

if [ "$PAGERCTL_FOUND" = false ]; then
    LOG ""; LOG "red" "=== MISSING DEPENDENCY ==="
    LOG "red" "libpagerctl.so / pagerctl.py not found!"
    LOG "Install PAGERCTL or copy files to: $PAYLOAD_DIR/lib/"
    LOG ""; LOG "Press any button to exit..."
    WAIT_FOR_INPUT >/dev/null 2>&1
    exit 1
fi

if [ "$PAGERCTL_DIR" != "$PAYLOAD_DIR/lib" ]; then
    mkdir -p "$PAYLOAD_DIR/lib" 2>/dev/null
    cp "$PAGERCTL_DIR/libpagerctl.so" "$PAYLOAD_DIR/lib/" 2>/dev/null
    cp "$PAGERCTL_DIR/pagerctl.py"    "$PAYLOAD_DIR/lib/" 2>/dev/null
fi

# ── Environment ───────────────────────────────────────────────────
export PATH="/mmc/usr/bin:$PAYLOAD_DIR/bin:$PATH"
export PYTHONPATH="$PAYLOAD_DIR/lib:$PAYLOAD_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:$PAYLOAD_DIR/lib:$LD_LIBRARY_PATH"

# ── Python ────────────────────────────────────────────────────────
check_python() {
    NEED_PYTHON=false
    NEED_CTYPES=false

    if ! command -v python3 >/dev/null 2>&1; then
        NEED_PYTHON=true
        NEED_CTYPES=true
    elif ! python3 -c "import ctypes" 2>/dev/null; then
        NEED_CTYPES=true
    fi

    if [ "$NEED_PYTHON" = true ] || [ "$NEED_CTYPES" = true ]; then
        LOG ""
        LOG "red" "=== PYTHON3 REQUIRED ==="
        LOG ""
        if [ "$NEED_PYTHON" = true ]; then
            LOG "Python3 is not installed."
        else
            LOG "Python3-ctypes is not installed."
        fi
        LOG ""
        LOG "green" "GREEN = Install (requires internet)"
        LOG "red"   "RED   = Exit"
        LOG ""

        while true; do
            BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
            case "$BUTTON" in
                "GREEN"|"A")
                    LOG ""
                    LOG "Updating package lists..."
                    opkg update 2>&1 | while IFS= read -r line; do LOG "  $line"; done
                    LOG ""
                    LOG "Installing Python3 + ctypes to MMC..."
                    opkg -d mmc install python3 python3-ctypes 2>&1 | while IFS= read -r line; do LOG "  $line"; done
                    LOG ""
                    if command -v python3 >/dev/null 2>&1 && python3 -c "import ctypes" 2>/dev/null; then
                        LOG "green" "Python3 installed successfully!"
                        sleep 1
                        return 0
                    else
                        LOG "red" "Installation failed."
                        LOG "Check internet connection."
                        sleep 2
                        return 1
                    fi
                    ;;
                "RED"|"B")
                    LOG "Exiting."
                    exit 0
                    ;;
            esac
        done
    fi
    return 0
}

check_python || exit 1
PYTHON=$(command -v python3)

# ── SSH direct modes ──────────────────────────────────────────────
case "$1" in
    --stop)
        for f in "$BLE_PID" "$ANA_PID" "$WIFI_PID" "$WEB_PID"; do
            [ -f "$f" ] || continue
            pid=$(cat "$f" 2>/dev/null)
            [ -n "$pid" ] && kill "$pid" 2>/dev/null
            rm -f "$f"
        done
        echo "[CYT] Stopped."
        exit 0
        ;;
    --status)
        for name in ble analyzer wifi web; do
            f="$PAYLOAD_DIR/$name.pid"
            [ -f "$f" ] && pid=$(cat "$f" 2>/dev/null) || pid=""
            [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null \
                && echo "  $name: RUNNING (pid $pid)" \
                || echo "  $name: stopped"
        done
        exit 0
        ;;
    --headless)
        # SSH headless: start daemons, stay running
        shift
        ;;
esac

# ── Helpers ───────────────────────────────────────────────────────
pid_alive() {
    [ -f "$1" ] || return 1
    local pid; pid=$(cat "$1" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

cyt_running() {
    pid_alive "$BLE_PID" || pid_alive "$WIFI_PID" || pid_alive "$ANA_PID"
}

stop_all() {
    for f in "$BLE_PID" "$ANA_PID" "$WIFI_PID" "$WEB_PID"; do
        [ -f "$f" ] || continue
        pid=$(cat "$f" 2>/dev/null)
        [ -n "$pid" ] && kill "$pid" 2>/dev/null
        rm -f "$f"
    done
}

# Wait for a pidfile to appear (max N*0.1 seconds), then verify process is alive
wait_daemon() {
    local pidfile="$1" max="${2:-30}" i=0
    while [ $i -lt "$max" ]; do
        pid_alive "$pidfile" && return 0
        sleep 0.1
        i=$((i + 1))
    done
    return 1
}

start_daemons() {
    local with_web="${1:-yes}"

    uci set gpsd.core.device='/dev/ttyACM0' 2>/dev/null
    uci commit gpsd 2>/dev/null
    /etc/init.d/gpsd restart 2>/dev/null || \
        /usr/sbin/gpsd -n -b /dev/ttyACM0 2>/dev/null &

    hciconfig hci1 down 2>/dev/null; sleep 0.5
    hciconfig hci1 up   2>/dev/null; sleep 0.5

    pid_alive "$BLE_PID" || {
        "$PYTHON" "$PAYLOAD_DIR/ble_scanner.py" \
            --db "$DB" --hci 1 --daemon --pidfile "$BLE_PID"
        wait_daemon "$BLE_PID" 20   # up to 2s
    }
    pid_alive "$WIFI_PID" || {
        "$PYTHON" "$PAYLOAD_DIR/wifi_scanner.py" \
            --db "$DB" --iface wlan0mon --daemon --pidfile "$WIFI_PID"
        wait_daemon "$WIFI_PID" 20  # up to 2s
    }
    pid_alive "$ANA_PID" || {
        "$PYTHON" "$PAYLOAD_DIR/analyzer.py" \
            --db "$DB" --log "$CYT_LOG" --status "$STATUS_JSON" \
            --interval 30 --window 3600 \
            --daemon --pidfile "$ANA_PID"
        wait_daemon "$ANA_PID" 20   # up to 2s
    }
    [ "$with_web" = "yes" ] && ! pid_alive "$WEB_PID" && {
        "$PYTHON" "$PAYLOAD_DIR/web_server.py" \
            --db "$DB" --status "$STATUS_JSON" \
            --port 8080 --daemon --pidfile "$WEB_PID"
        wait_daemon "$WEB_PID" 15   # up to 1.5s
    }
}

# ── Cleanup trap ──────────────────────────────────────────────────
cleanup() {
    if ! pgrep -x pineapple >/dev/null; then
        /etc/init.d/pineapplepager start 2>/dev/null
    fi
}
trap cleanup EXIT

# ── Info screen ───────────────────────────────────────────────────
LOG ""
LOG "green" "Chasing Your Tail v1.0"
LOG "cyan"  "Passive Surveillance Detection"
LOG ""
LOG "yellow" "Tracks BLE, WiFi + Drone devices"
LOG "yellow" "that follow you across locations."
LOG ""

if cyt_running; then
    LOG "green" "CYT is running in the background."
    LOG ""
    LOG "green"  "GREEN = Open GUI"
    LOG "yellow" "DOWN  = Stop CYT"
    LOG "red"    "RED   = Exit"
    LOG ""

    RUN_MODE="none"
    while true; do
        BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
        case "$BUTTON" in
            "GREEN"|"A") RUN_MODE="gui";  break ;;
            "DOWN")
                SPINNER_ID=$(START_SPINNER "Stopping CYT...")
                stop_all
                STOP_SPINNER "$SPINNER_ID" 2>/dev/null
                LOG "green" "CYT stopped."
                sleep 1
                exit 0
                ;;
            "RED"|"B") exit 0 ;;
        esac
    done
else
    LOG "green"  "GREEN = Start GUI"
    LOG "yellow" "UP    = Run headless"
    LOG "red"    "RED   = Exit"
    LOG ""

    RUN_MODE="none"
    while true; do
        BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
        case "$BUTTON" in
            "GREEN"|"A") RUN_MODE="gui";      break ;;
            "UP")        RUN_MODE="headless"; break ;;
            "RED"|"B")   LOG "Exiting."; exit 0 ;;
        esac
    done
fi

# ── Headless mode ─────────────────────────────────────────────────
if [ "$RUN_MODE" = "headless" ]; then
    LOG ""
    LOG "green" "Start web UI?"
    LOG "green" "GREEN = Yes"
    LOG "red"   "RED   = No"
    LOG ""
    WEB_UI="no"
    while true; do
        BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
        case "$BUTTON" in
            "GREEN"|"A") WEB_UI="yes"; break ;;
            "RED"|"B")   WEB_UI="no";  break ;;
        esac
    done

    SPINNER_ID=$(START_SPINNER "Starting CYT...")
    start_daemons "$WEB_UI"
    STOP_SPINNER "$SPINNER_ID" 2>/dev/null

    LOG ""
    LOG "green" "CYT running in background."
    [ "$WEB_UI" = "yes" ] && LOG "cyan" "Web: http://172.16.52.1:8080"
    LOG ""
    LOG "yellow" "CYT keeps running after exit."
    LOG "red"    "RED = Exit"
    LOG ""
    while true; do
        BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
        case "$BUTTON" in "RED"|"B") break ;; esac
    done
    exit 0
fi

# ── GUI mode ──────────────────────────────────────────────────────
# Stop pineapple and launch immediately — must be fast (sleep 0.5 < procd 1s respawn)
# cyt_app.py handles daemon startup from its own start menu
SPINNER_ID=$(START_SPINNER "Loading GUI...")
/etc/init.d/pineapplepager stop 2>/dev/null
sleep 0.5
STOP_SPINNER "$SPINNER_ID" 2>/dev/null

while true; do
    "$PYTHON" "$PAYLOAD_DIR/cyt_app.py" --db "$DB" --limit 20
    EXIT_CODE=$?
    [ "$EXIT_CODE" -eq 99 ] && continue   # restart startup menu
    [ "$EXIT_CODE" -eq 1  ] && stop_all   # user chose Stop CYT
    break
done
