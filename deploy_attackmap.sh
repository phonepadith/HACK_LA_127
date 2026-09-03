#!/bin/sh
# Deploy the GeoIP Attack Map + Logstash stack to the CEIT server (Docker).
# Runs entirely as containers in project "geoai-attackmap" — no host changes.
set -e
HOST=administrator@202.137.130.115
PORT=2222
DIR=/home/administrator/geoai-attackmap

cd "$(dirname "$0")/attackmap"
[ -f db/GeoLite2-City.mmdb ] || { echo "missing db/GeoLite2-City.mmdb"; exit 1; }

echo "Syncing stack to CEIT..."
rsync -az -e "ssh -p $PORT" --exclude 'shared/*.log' ./ "$HOST:$DIR/"

ssh -p $PORT $HOST "
  set -e
  cd $DIR
  mkdir -p shared && : > shared/attack.log
  docker compose up -d --build
  echo 'waiting for map server...'
  for i in \$(seq 1 30); do
    curl -sf localhost:8899/ >/dev/null 2>&1 && { echo 'MAP UP'; break; }
    sleep 2
  done
  docker compose ps
"
echo "Attack map: tunnel a subdomain to localhost:8899 on CEIT"
