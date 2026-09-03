#!/usr/bin/env python3
"""Patch the geoip-attack-map DataServer for a containerized environment:
read config from env vars and drop the must-run-as-root check."""
import re
import sys

path = sys.argv[1]
src = open(path).read()

# make config env-driven
src = src.replace("redis_ip = '127.0.0.1'",
                  "import os\nredis_ip = os.environ.get('REDIS_HOST', '127.0.0.1')")
src = src.replace("syslog_path = '/var/log/syslog'",
                  "syslog_path = os.environ.get('SYSLOG_PATH', '/var/log/syslog')")
src = src.replace("db_path = '../DataServerDB/GeoLite2-City.mmdb'",
                  "db_path = os.environ.get('DB_PATH', '../DataServerDB/GeoLite2-City.mmdb')")
src = src.replace("hq_ip = '8.8.8.8'",
                  "hq_ip = os.environ.get('HQ_IP', '8.8.8.8')")

# containers run as root already; neutralise the getuid guard either way
src = re.sub(r"if getuid\(\) != 0:", "if False:", src)

open(path, "w").write(src)
print("patched", path)
