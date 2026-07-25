#!/bin/bash
# Auto-update subscription every 6 hours
INTERVAL=3600  # 1 hour in seconds
SCRIPT_DIR="/workspace"

while true; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running subscription update..."
    python3 "$SCRIPT_DIR/update_subscription.py" 2>&1
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Done. Sleeping ${INTERVAL}s..."
    sleep $INTERVAL
done
