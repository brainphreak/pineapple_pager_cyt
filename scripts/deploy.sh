#!/bin/bash
# deploy.sh — Deploy CYT payload to Pineapple Pager
# Usage: ./scripts/deploy.sh [user@host]

DEVICE="${1:-root@172.16.52.1}"
DEVICE_PATH="/mmc/root/payloads/reconnaissance/cyt"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD_DIR="$(dirname "$SCRIPT_DIR")/library/payloads/reconnaissance/cyt"

echo "=== Deploying CYT to $DEVICE:$DEVICE_PATH ==="

# Create payload directory
ssh "$DEVICE" "mkdir -p '$DEVICE_PATH/lib'"

# Copy payload files
scp -r "$PAYLOAD_DIR/" "$DEVICE:$(dirname $DEVICE_PATH)/"

# Set permissions
ssh "$DEVICE" "chmod +x '$DEVICE_PATH/payload.sh'"

echo ""
echo "=== Deploy complete ==="
echo "Run on device:"
echo "  GUI mode:      $DEVICE_PATH/payload.sh"
echo "  Headless mode: $DEVICE_PATH/payload.sh --headless"
echo "  Status:        $DEVICE_PATH/payload.sh --status"
echo "  Stop:          $DEVICE_PATH/payload.sh --stop"
