#!/usr/bin/env bash
set -e
cd /var/www/zqzx
pkill -f "node server.js" || true
sleep 2
node server.js

echo "Restart script finished."
