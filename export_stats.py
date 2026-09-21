#!/usr/bin/env python3
"""Export GeoAI attack statistics from a running server to CSV files in data/.

    python3 export_stats.py                                  # production
    python3 export_stats.py --url http://localhost:8000      # local instance

Credentials come from GEOAI_USER / GEOAI_PASS (same defaults as the server).
Stdlib only, like the rest of the platform.
"""
import csv
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

URL = "https://geoai-ftth-demo.laopadit.com"
if "--url" in sys.argv:
    URL = sys.argv[sys.argv.index("--url") + 1]
URL = URL.rstrip("/")
OUT = Path(__file__).with_name("data")
# Cloudflare in front of production 403s the default python-urllib agent
HEADERS = {"User-Agent": "geoai-export/1.0"}
USER = os.environ.get("GEOAI_USER", "admin")
PASS = os.environ.get("GEOAI_PASS", "geoai2026")


def get(path, token):
    req = urllib.request.Request(URL + path, headers={"X-Auth": token, **HEADERS})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def write(name, header, rows):
    path = OUT / name
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"  {path.relative_to(Path(__file__).parent)}  ({len(rows)} rows)")
    return len(rows)


def main():
    OUT.mkdir(exist_ok=True)
    body = json.dumps({"user": USER, "pass": PASS}).encode()
    req = urllib.request.Request(URL + "/api/login", data=body,
                                 headers={"Content-Type": "application/json", **HEADERS})
    with urllib.request.urlopen(req, timeout=30) as r:
        token = json.load(r)["token"]

    stamp = time.strftime("%Y-%m-%d %H:%M:%S%z")
    print(f"{URL} @ {stamp}")

    series, by_zone = [], []
    for rng in ("day", "month", "year"):
        s = get(f"/api/stats?range={rng}", token)
        series += [(rng, lbl, n) for lbl, n in zip(s["labels"], s["attacks"])]
        by_zone += [(rng, "target", z["name"], z["count"]) for z in s["by_zone"]]
        by_zone += [(rng, "origin", z["name"], z["count"]) for z in s["by_origin"]]

    write("attacks_timeseries.csv", ["range", "bucket", "attacks"], series)
    write("attacks_by_zone.csv", ["range", "direction", "zone", "attacks"], by_zone)

    st = get("/api/state", token)
    alerts = {a["olt"]: a for a in st["alerts"]}
    counts = {}
    for o in st["onts"]:
        c = counts.setdefault(o["olt"], {"total": 0, "compromised": 0, "suspicious": 0})
        c["total"] += 1
        if o["status"] in c:
            c[o["status"]] += 1
    write("zone_status.csv",
          ["zone_id", "zone", "risk", "onts", "compromised", "suspicious", "severity",
           "attack_origin", "alert_since"],
          [(z["id"], z["name"], z.get("risk", 0),
            counts.get(z["id"], {}).get("total", 0),
            counts.get(z["id"], {}).get("compromised", 0),
            counts.get(z["id"], {}).get("suspicious", 0),
            alerts.get(z["id"], {}).get("severity", ""),
            alerts.get(z["id"], {}).get("origin", ""),
            alerts.get(z["id"], {}).get("since", ""))
           for z in st["olts"]])
    write("attacker_sources.csv", ["ip", "hits"],
          [(i["ip"], i["hits"]) for i in st["top_ips"]])

    (OUT / "EXPORT.txt").write_text(
        f"source: {URL}\nexported: {stamp}\nmode: {st['mode']}\n"
        f"server time: {st['time']}\nattacks_detected: {st['stats']['attacks_detected']}\n"
        f"onts_recovered: {st['stats']['onts_recovered']}\n")
    print(f"  data/EXPORT.txt")


if __name__ == "__main__":
    main()
