#!/bin/sh
# Deploy the GeoAI edge sensor to the Raspberry Pi and (re)start it.
# Prompts for the Pi's SSH password unless key auth is set up:
#   ssh-copy-id kobi@192.168.0.110
#
# GEOAI_URL is where the sensor finds the ONT/GeoAI server (default: this
# Mac's simulator). Override:  GEOAI_URL=http://host:port ./deploy_pi.sh
set -e
PI=kobi@192.168.0.110
DIR=/home/kobi/geoai-sensor
URL=${GEOAI_URL:-http://192.168.0.111:8000}

cd "$(dirname "$0")"
tar cz pi_agent.py | ssh $PI "
  set -e
  mkdir -p $DIR
  tar xz -C $DIR
  fuser -k 8080/tcp 2>/dev/null || true
  sleep 1
  cd $DIR
  GEOAI_URL=$URL nohup python3 pi_agent.py > agent.log 2>&1 < /dev/null &
  sleep 2
  if curl -sf localhost:8080/pi/state > /dev/null 2>&1; then
    echo 'SENSOR DEPLOYED — monitor UI: http://192.168.0.110:8080'
  else
    echo 'DEPLOY FAILED — last log lines:'; tail -5 agent.log; exit 1
  fi
"
