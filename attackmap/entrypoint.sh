#!/bin/sh
set -e
# ensure the tailed file exists before DataServer opens it
: > "${SYSLOG_PATH:-/shared/attack.log}" 2>/dev/null || true

# DataServer: tail the shared file, GeoIP-enrich, aggregate, publish to Redis
cd /app/repo/DataServer
python DataServer.py &

# MapServer: serve the project's frontend + bridge Redis -> websockets
cd /app
exec python mapserver.py
