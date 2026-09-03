#!/bin/sh
# Deploy GeoAI SOC to CEIT-LTC-SERVER and (re)start it on port 3030.
# Prompts for the SSH password once. For passwordless deploys, run once:
#   ssh-copy-id -p 2222 administrator@202.137.130.115
set -e
HOST=administrator@202.137.130.115
PORT=2222
DIR=/home/administrator/fen-site/geoai
APP_PORT=3030

cd "$(dirname "$0")"
tar cz simulator.py dashboard.html README.md | ssh -p $PORT $HOST "
  set -e
  mkdir -p $DIR
  tar xz -C $DIR
  fuser -k $APP_PORT/tcp 2>/dev/null || true
  sleep 1
  cd $DIR
  LOGSTASH_HOST=127.0.0.1 LOGSTASH_PORT=5055 setsid nohup python3 simulator.py --port $APP_PORT > geoai.log 2>&1 < /dev/null &
  sleep 2
  if curl -sf localhost:$APP_PORT/ > /dev/null 2>&1 \
     || python3 -c 'import urllib.request as u; u.urlopen(\"http://localhost:$APP_PORT/\")' 2>/dev/null; then
    echo 'DEPLOYED OK — dashboard: http://202.137.130.115:$APP_PORT'
  else
    echo 'DEPLOY FAILED — last log lines:'; tail -5 geoai.log; exit 1
  fi
"
