#!/bin/sh
# docker_build.sh — Runs inside the mipsel-cross:latest container
# Called by: docker run ... mipsel-cross:latest sh /project/scripts/docker_build.sh
#
# Builds all CYT binaries and places them in /project/build/

set -e

export PATH=/opt/mipsel-linux-muslsf-cross/bin:$PATH
CC=mipsel-linux-muslsf-gcc
STRIP=mipsel-linux-muslsf-strip

SRC=/project/src
BUILD=/project/build

mkdir -p "$BUILD"

# Common CFLAGS
CFLAGS="-static -O2 -Wall \
    -DSQLITE_THREADSAFE=0 \
    -DSQLITE_DEFAULT_MEMSTATUS=0 \
    -DSQLITE_OMIT_LOAD_EXTENSION \
    -I$SRC"

# SQLite needs these to avoid pulling in pthreads/dl
SQLITE_FLAGS="-DSQLITE_THREADSAFE=0 \
    -DSQLITE_DEFAULT_MEMSTATUS=0 \
    -DSQLITE_OMIT_LOAD_EXTENSION \
    -DSQLITE_OMIT_SHARED_CACHE \
    -DSQLITE_OMIT_WAL=0"

echo "=== Building ble_scanner ==="
$CC $CFLAGS \
    "$SRC/ble_scanner.c" \
    "$SRC/db.c" \
    "$SRC/sqlite3.c" \
    -I"$SRC" \
    $SQLITE_FLAGS \
    -lbluetooth \
    -o "$BUILD/ble_scanner"
$STRIP "$BUILD/ble_scanner"
echo "  -> $BUILD/ble_scanner ($(ls -lh $BUILD/ble_scanner | awk '{print $5}'))"

echo "=== Building analyzer ==="
$CC $CFLAGS \
    "$SRC/analyzer.c" \
    "$SRC/db.c" \
    "$SRC/sqlite3.c" \
    $SQLITE_FLAGS \
    -o "$BUILD/analyzer"
$STRIP "$BUILD/analyzer"
echo "  -> $BUILD/analyzer ($(ls -lh $BUILD/analyzer | awk '{print $5}'))"

echo "=== Building cyt_ui (headless/text mode) ==="
$CC $CFLAGS \
    "$SRC/cyt_ui.c" \
    "$SRC/db.c" \
    "$SRC/sqlite3.c" \
    $SQLITE_FLAGS \
    -o "$BUILD/cyt_ui"
$STRIP "$BUILD/cyt_ui"
echo "  -> $BUILD/cyt_ui ($(ls -lh $BUILD/cyt_ui | awk '{print $5}'))"

echo "=== Building wifi_scanner ==="
$CC $CFLAGS \
    "$SRC/wifi_scanner.c" \
    "$SRC/db.c" \
    "$SRC/sqlite3.c" \
    $SQLITE_FLAGS \
    -o "$BUILD/wifi_scanner" || {
    echo "  WARNING: wifi_scanner build failed (non-fatal)"
}

if [ -f "$BUILD/wifi_scanner" ]; then
    $STRIP "$BUILD/wifi_scanner"
    echo "  -> $BUILD/wifi_scanner ($(ls -lh $BUILD/wifi_scanner | awk '{print $5}'))"
fi

echo ""
echo "=== Build complete ==="
ls -lh "$BUILD/"
