#!/usr/bin/env python3
"""GeoAI FTTH Security Intelligence Platform — SOC monitoring prototype.

Detects FTTH ONT account-takeover attacks from authentication logs across all
18 Laos provinces, scores geographic risk per zone, tracks attacker source IPs
and origin provinces, keeps attack history for day/month/year statistics, and
supports one-click batch recovery via a (stubbed) ACS.

Modes:
  python3 simulator.py            demo: built-in attack simulator drives it
  python3 simulator.py --live     real case: only ingested logs drive it

Real log ingestion (either mode):
  curl -X POST localhost:8000/api/log -d \
    '{"device":"VTE-ONT-001","type":"login_fail","src_ip":"203.0.113.9"}'
  types: login_fail | cred_change | login_ok    (accepts one event or a list)

Real ONT inventory: put a devices.csv next to this file
  id,olt,olt_name,lat,lon

Self-check: python3 simulator.py --check
"""
import csv
import json
import os
import random
import secrets
import sys
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# --- Laos provinces (zone id, name, capital coordinates) ---------------------
PROVINCES = [
    {"id": "VTE", "name": "Vientiane Capital", "lat": 17.9757, "lon": 102.6331},
    {"id": "PSL", "name": "Phongsaly",         "lat": 21.6837, "lon": 102.1130},
    {"id": "LNT", "name": "Luang Namtha",      "lat": 20.9571, "lon": 101.4004},
    {"id": "ODX", "name": "Oudomxay",          "lat": 20.6923, "lon": 101.9840},
    {"id": "BKO", "name": "Bokeo",             "lat": 20.2775, "lon": 100.4133},
    {"id": "LPB", "name": "Luang Prabang",     "lat": 19.8834, "lon": 102.1347},
    {"id": "HPN", "name": "Houaphanh",         "lat": 20.4165, "lon": 104.0480},
    {"id": "XBY", "name": "Xayaboury",         "lat": 19.2576, "lon": 101.7103},
    {"id": "XKH", "name": "Xiengkhouang",      "lat": 19.4520, "lon": 103.2200},
    {"id": "VTP", "name": "Vientiane Province","lat": 18.4953, "lon": 102.4144},
    {"id": "BLX", "name": "Bolikhamxay",       "lat": 18.3711, "lon": 103.6600},
    {"id": "KHM", "name": "Khammouane",        "lat": 17.4074, "lon": 104.8050},
    {"id": "SVK", "name": "Savannakhet",       "lat": 16.5560, "lon": 104.7570},
    {"id": "SRV", "name": "Salavan",           "lat": 15.7166, "lon": 106.4200},
    {"id": "SEK", "name": "Sekong",            "lat": 15.3506, "lon": 106.7280},
    {"id": "CPS", "name": "Champasak",         "lat": 15.1205, "lon": 105.7987},
    {"id": "ATP", "name": "Attapeu",           "lat": 14.8110, "lon": 106.8320},
    {"id": "XSB", "name": "Xaysomboun",        "lat": 18.9037, "lon": 103.0919},
]

# --- Detection tuning (adjust to your network's real baseline) ---------------
WINDOW = 60           # seconds of auth-log history the detector looks at
SUSPICIOUS_FAILS = 5  # failed logins in window -> suspicious
TAKEOVER_FAILS = 8    # fails before the simulated attacker gets in
ALERT_MIN_AFFECTED = 3  # affected ONTs in a zone before a zone alert fires
IP_WINDOW = 300       # seconds of attacker source-IP history to aggregate
HISTORY_BACKFILL = 450  # synthetic past attacks seeded in demo mode


def load_devices(path=Path(__file__).with_name("devices.csv")):
    if not path.exists():
        return None
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


class Simulation:
    def __init__(self, seed=None, live=False, devices=None):
        rng = self.rng = random.Random(seed)
        self.lock = threading.Lock()
        self.live = live
        self.now = time.time() if live else 0.0
        self.onts, self.olts = {}, []
        if devices:
            zones = {}
            for d in devices:
                self.onts[d["id"]] = {
                    "id": d["id"], "olt": d["olt"],
                    "lat": float(d["lat"]), "lon": float(d["lon"]),
                    "status": "normal", "fails": [], "compromised_at": None,
                }
                zones.setdefault(d["olt"], {"name": d.get("olt_name") or d["olt"],
                                            "lats": [], "lons": []})
                zones[d["olt"]]["lats"].append(float(d["lat"]))
                zones[d["olt"]]["lons"].append(float(d["lon"]))
            self.olts = [{"id": z, "name": v["name"],
                          "lat": sum(v["lats"]) / len(v["lats"]),
                          "lon": sum(v["lons"]) / len(v["lons"])}
                         for z, v in zones.items()]
        else:
            self.olts = [dict(p) for p in PROVINCES]
            for p in self.olts:
                count = 40 if p["id"] == "VTE" else rng.randint(10, 16)
                for i in range(count):
                    oid = f"{p['id']}-ONT-{i+1:03d}"
                    self.onts[oid] = {
                        "id": oid, "olt": p["id"],
                        "lat": p["lat"] + rng.gauss(0, 0.05),
                        "lon": p["lon"] + rng.gauss(0, 0.05),
                        "status": "normal", "fails": [], "compromised_at": None,
                    }
        self.names = {o["id"]: o["name"] for o in self.olts}
        self.events = []      # recent log lines for the UI ticker
        self.alerts = {}      # zone id -> alert dict
        self.ip_hits = []     # (t, src_ip) of hostile auth attempts
        self.history = []     # attack records: {ts, target, origin} (epoch ts)
        self.attack = None    # demo attacker state
        self.sensors = {}     # edge sensor heartbeats: name -> {..., ts}
        self.auto_recover = False  # AI auto-approves batch recovery when on
        self.next_auto_attack = 15 + rng.uniform(0, 15)
        self.recovered_total = 0
        self.detected_attacks = 0
        if not live:
            self._backfill_history()

    def _backfill_history(self):
        """Seed a year of synthetic attack history so the statistics have data."""
        now = time.time()
        for _ in range(HISTORY_BACKFILL):
            ts = now - self.rng.random() ** 1.5 * 365 * 86400  # denser recently
            tgt = self.rng.choice(self.olts)
            org = self.rng.choice([o for o in self.olts if o["id"] != tgt["id"]])
            self.history.append({"ts": ts, "target": tgt["id"], "origin": org["id"]})

    def ts(self):
        return time.strftime("%H:%M:%S", time.localtime(self.now)) if self.live \
            else f"t={round(self.now, 1)}"

    def log(self, kind, msg, zone=None):
        self.events.append({"t": self.ts(), "kind": kind, "msg": msg, "zone": zone})
        del self.events[:-60]

    # --- real-case ingestion --------------------------------------------------
    def ingest(self, evts):
        """Accept auth events from real OLT/ACS/RADIUS collectors."""
        if isinstance(evts, dict):
            evts = [evts]
        n = 0
        with self.lock:
            for e in evts:
                ont = self.onts.get(str(e.get("device", "")))
                if not ont:
                    continue
                typ = e.get("type")
                if typ == "login_fail":
                    ont["fails"].append(self.now)
                    if e.get("src_ip"):
                        self.ip_hits.append((self.now, e["src_ip"]))
                elif typ == "cred_change" and ont["status"] != "compromised":
                    ont["status"] = "compromised"
                    ont["compromised_at"] = self.now
                    if e.get("src_ip"):
                        self.ip_hits.append((self.now, e["src_ip"]))
                    self.log("compromise",
                             f"{ont['id']}: credential change reported — service down",
                             ont["olt"])
                n += 1
            self._detect()
        return n

    # --- demo attack generation ------------------------------------------------
    def start_attack(self, olt_id=None):
        if self.attack:
            return
        olt_id = olt_id or self.rng.choice(self.olts)["id"]
        origin = self.rng.choice([o for o in self.olts if o["id"] != olt_id])
        pool = [o for o in self.onts.values() if o["olt"] == olt_id]
        targets = [o["id"] for o in
                   self.rng.sample(pool, self.rng.randint(min(8, len(pool)), min(20, len(pool))))]
        ips = [f"203.0.113.{self.rng.randint(1, 254)}" for _ in range(self.rng.randint(1, 3))]
        self.attack = {"olt": olt_id, "origin": origin["id"], "targets": targets, "ips": ips}
        self.log("attack", f"[hidden] attacker in {origin['name']} begins "
                           f"credential-stuffing sweep against {self.names[olt_id]}", olt_id)

    def tick(self, dt=1.0):
        with self.lock:
            self.now = time.time() if self.live else self.now + dt
            rng = self.rng
            if not self.live:
                # background noise: occasional legit failed logins
                for ont in rng.sample(list(self.onts.values()), min(6, len(self.onts))):
                    if rng.random() < 0.3 and ont["status"] == "normal":
                        ont["fails"].append(self.now)
                # auto-spawn attacks so the demo runs itself
                if not self.attack and self.now >= self.next_auto_attack:
                    self.start_attack()
                    self.next_auto_attack = self.now + 45 + rng.uniform(0, 45)
                # active attack: hammer targets, take over after enough fails
                if self.attack:
                    remaining = [t for t in self.attack["targets"]
                                 if self.onts[t]["status"] != "compromised"]
                    if not remaining:
                        self.attack = None
                    else:
                        for tid in rng.sample(remaining, min(4, len(remaining))):
                            ont = self.onts[tid]
                            hits = rng.randint(1, 3)
                            ont["fails"] += [self.now] * hits
                            self.ip_hits += [(self.now, rng.choice(self.attack["ips"]))] * hits
                            recent = [f for f in ont["fails"] if f > self.now - WINDOW]
                            if len(recent) >= TAKEOVER_FAILS:
                                ont["status"] = "compromised"
                                ont["compromised_at"] = self.now
                                self.log("compromise",
                                         f"{tid}: credentials changed by attacker — service down",
                                         ont["olt"])
            self._detect()

    # --- AI detection + GeoAI zone scoring -------------------------------------
    def _detect(self):
        self.ip_hits = [h for h in self.ip_hits if h[0] > self.now - IP_WINDOW]
        for ont in self.onts.values():
            ont["fails"] = [f for f in ont["fails"] if f > self.now - WINDOW]
            if ont["status"] == "compromised":
                continue
            if len(ont["fails"]) >= SUSPICIOUS_FAILS:
                if ont["status"] != "suspicious":
                    ont["status"] = "suspicious"
                    self.log("detect", f"AI: abnormal login pattern on {ont['id']} "
                                       f"({len(ont['fails'])} fails/{WINDOW}s)", ont["olt"])
            else:
                ont["status"] = "normal"
        # GeoAI: per-zone risk score and alerts
        for olt in self.olts:
            zone = [o for o in self.onts.values() if o["olt"] == olt["id"]]
            comp = sum(o["status"] == "compromised" for o in zone)
            susp = sum(o["status"] == "suspicious" for o in zone)
            risk = min(1.0, (comp + 0.5 * susp) / max(1, len(zone)) * 3)
            affected = comp + susp
            alert = self.alerts.get(olt["id"])
            if affected >= ALERT_MIN_AFFECTED:
                sev = ("critical" if risk > 0.6 else "high" if risk > 0.35
                       else "medium" if risk > 0.15 else "low")
                origin = (self.attack["origin"]
                          if self.attack and self.attack["olt"] == olt["id"] else None)
                if not alert:
                    self.detected_attacks += 1
                    self.history.append({"ts": time.time(), "target": olt["id"],
                                         "origin": origin or "unknown"})
                    self.log("alert", f"GeoAI: attack hotspot detected in {olt['name']} "
                                      f"({olt['id']}) — {affected} ONTs affected", olt["id"])
                self.alerts[olt["id"]] = {
                    "olt": olt["id"], "zone": olt["name"], "severity": sev,
                    "risk": round(risk, 2), "compromised": comp, "suspicious": susp,
                    "origin": self.names.get(origin, alert["origin"] if alert else "unknown"),
                    "since": alert["since"] if alert else self.ts(),
                    "action": f"Batch-reset {comp} ONTs to ISP defaults via ACS",
                }
                if self.auto_recover and comp >= ALERT_MIN_AFFECTED:
                    self.log("ai", f"AI auto-approved batch recovery for {olt['name']} "
                                   f"({comp} compromised, risk {round(risk, 2)})", olt["id"])
                    self._do_recover(olt["id"], by="AI auto-approved")
            elif alert and comp == 0:
                del self.alerts[olt["id"]]
            olt["risk"] = risk

    # --- automated recovery -----------------------------------------------------
    def _do_recover(self, olt_id, by="operator"):
        n = 0
        for ont in self.onts.values():
            if ont["olt"] == olt_id and ont["status"] != "normal":
                ont["status"] = "normal"
                ont["fails"] = []
                ont["compromised_at"] = None
                n += 1
        self.recovered_total += n
        self.alerts.pop(olt_id, None)
        if self.attack and self.attack["olt"] == olt_id:
            self.attack = None
        # ponytail: ACS stub — wire your vendor's TR-069/NETCONF API here
        self.log("recover", f"ACS: batch config push reset {n} ONTs in "
                            f"{self.names.get(olt_id, olt_id)} — service up ({by})", olt_id)
        return n

    def recover(self, olt_id, by="operator"):
        with self.lock:
            return self._do_recover(olt_id, by)

    # --- statistics for the analytics view ---------------------------------------
    def stats_range(self, rng="day"):
        now = time.time()
        lt = time.localtime
        if rng == "year":
            t = lt(now)
            keys = []
            y, m = t.tm_year, t.tm_mon
            for i in range(11, -1, -1):
                mm, yy = m - i, y
                while mm <= 0:
                    mm += 12
                    yy -= 1
                keys.append(f"{yy}-{mm:02d}")
            bucket = lambda ts: f"{lt(ts).tm_year}-{lt(ts).tm_mon:02d}"
            cutoff = now - 366 * 86400
        elif rng == "month":
            keys = [time.strftime("%m-%d", lt(now - i * 86400)) for i in range(29, -1, -1)]
            bucket = lambda ts: time.strftime("%m-%d", lt(ts))
            cutoff = now - 30 * 86400
        else:  # day
            keys = [time.strftime("%Hh", lt(now - i * 3600)) for i in range(23, -1, -1)]
            bucket = lambda ts: time.strftime("%Hh", lt(ts))
            cutoff = now - 24 * 3600
        with self.lock:
            recent = [h for h in self.history if h["ts"] >= cutoff]
            counts = Counter(bucket(h["ts"]) for h in recent)
            by_zone = Counter(self.names.get(h["target"], h["target"]) for h in recent)
            by_origin = Counter(self.names.get(h["origin"], "Unknown") for h in recent)
            return {
                "range": rng, "labels": keys,
                "attacks": [counts.get(k, 0) for k in keys],
                "total": len(recent),
                "by_zone": [{"name": n, "count": c} for n, c in by_zone.most_common(10)],
                "by_origin": [{"name": n, "count": c} for n, c in by_origin.most_common(10)],
            }

    def state(self):
        with self.lock:
            comp = sum(o["status"] == "compromised" for o in self.onts.values())
            susp = sum(o["status"] == "suspicious" for o in self.onts.values())
            top_ips = Counter(ip for _, ip in self.ip_hits).most_common(5)
            attack = None
            if self.attack:
                org = next(o for o in self.olts if o["id"] == self.attack["origin"])
                tgt = next(o for o in self.olts if o["id"] == self.attack["olt"])
                attack = {"zone": tgt["id"],
                          "from": {"name": org["name"], "lat": org["lat"], "lon": org["lon"]},
                          "to": {"name": tgt["name"], "lat": tgt["lat"], "lon": tgt["lon"]}}
            now = time.time()
            sensors = [dict(s, online=now - s["ts"] < 15, age=int(now - s["ts"]))
                       for s in self.sensors.values()]
            return {
                "time": self.ts(),
                "mode": "live" if self.live else "simulation",
                "auto_recover": self.auto_recover,
                "sensors": sensors,
                "olts": [dict(o, risk=round(o.get("risk", 0), 2)) for o in self.olts],
                "onts": [{k: o[k] for k in ("id", "olt", "lat", "lon", "status")}
                         for o in self.onts.values()],
                "alerts": sorted(self.alerts.values(), key=lambda a: -a["risk"]),
                "events": self.events[::-1],
                "attack": attack,
                "top_ips": [{"ip": ip, "hits": c} for ip, c in top_ips],
                "stats": {
                    "total": len(self.onts), "compromised": comp,
                    "suspicious": susp, "alerts": len(self.alerts),
                    "attacks_detected": self.detected_attacks,
                    "onts_recovered": self.recovered_total,
                },
            }


# --- HTTP server -------------------------------------------------------------
SIM = None
DASHBOARD = Path(__file__).with_name("dashboard.html")
# ponytail: single shared login, in-memory tokens — swap for real accounts/JWT
# when this needs per-operator audit trails
AUTH_USER = os.environ.get("GEOAI_USER", "admin")
AUTH_PASS = os.environ.get("GEOAI_PASS", "geoai2026")
TOKENS = set()


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, ctype="application/json", status=200):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authed(self):
        return self.headers.get("X-Auth") in TOKENS

    def do_GET(self):
        url = urlparse(self.path)
        if url.path.startswith("/api/") and not self._authed():
            return self._send({"error": "unauthorized"}, status=401)
        if url.path == "/api/state":
            self._send(SIM.state())
        elif url.path == "/api/stats":
            rng = parse_qs(url.query).get("range", ["day"])[0]
            self._send(SIM.stats_range(rng))
        elif url.path in ("/", "/index.html"):
            self._send(DASHBOARD.read_bytes(), "text/html; charset=utf-8")
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/api/login":
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            except ValueError:
                return self.send_error(400, "expected login json")
            if body.get("user") == AUTH_USER and body.get("pass") == AUTH_PASS:
                tok = secrets.token_hex(16)
                TOKENS.add(tok)
                return self._send({"ok": True, "token": tok, "user": AUTH_USER})
            return self._send({"ok": False}, status=401)
        if not self._authed():
            return self._send({"error": "unauthorized"}, status=401)
        if self.path == "/api/sensor":
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                name = str(body["name"])[:64]
            except (ValueError, KeyError):
                return self.send_error(400, "bad sensor heartbeat")
            with SIM.lock:
                known = name in SIM.sensors
                SIM.sensors[name] = {k: body.get(k) for k in
                                     ("name", "site", "lat", "lon", "cpu", "ram",
                                      "temp", "recovered")}
                SIM.sensors[name]["ts"] = time.time()
                if not known:
                    SIM.log("ai", f"edge sensor {name} registered"
                                  + (f" at {body.get('site')}" if body.get("site") else ""))
            self._send({"ok": True})
        elif self.path == "/api/log":
            try:
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                n = SIM.ingest(json.loads(body))
            except (ValueError, KeyError):
                return self.send_error(400, "bad event json")
            self._send({"ok": True, "ingested": n})
        elif self.path == "/api/auto":
            try:
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                enabled = bool(json.loads(body).get("enabled"))
            except (ValueError, AttributeError):
                return self.send_error(400, "expected {\"enabled\": bool}")
            with SIM.lock:
                if enabled != SIM.auto_recover:
                    SIM.auto_recover = enabled
                    SIM.log("ai", f"AI auto-approval {'ENABLED' if enabled else 'DISABLED'} "
                                  f"by operator")
            self._send({"ok": True, "auto_recover": enabled})
        elif self.path == "/api/attack":
            with SIM.lock:
                SIM.start_attack()
            self._send({"ok": True})
        elif self.path.startswith("/api/recover/"):
            url = urlparse(self.path)
            olt = url.path.rsplit("/", 1)[1]
            by = parse_qs(url.query).get("by", ["operator"])[0][:48]
            self._send({"ok": True, "reset": SIM.recover(olt, by)})
        else:
            self.send_error(404)

    def log_message(self, *a):  # quiet
        pass


def run_server(port=8000, live=False):
    global SIM
    SIM = Simulation(live=live, devices=load_devices())
    threading.Thread(target=lambda: [SIM.tick() or time.sleep(1) for _ in iter(int, 1)],
                     daemon=True).start()
    mode = "LIVE ingest" if live else "demo simulation"
    print(f"GeoAI FTTH SOC ({mode}, {len(SIM.onts)} ONTs, "
          f"{len(SIM.olts)} zones) on http://localhost:{port}")
    ThreadingHTTPServer(("", port), Handler).serve_forever()


def check():
    # demo attack lifecycle across provinces
    sim = Simulation(seed=42)
    sim.next_auto_attack = float("inf")
    sim.start_attack("VTE")
    for _ in range(5):
        sim.tick()
    mid = sim.state()
    assert mid["attack"] and mid["attack"]["from"]["name"], "no attack origin line data"
    for _ in range(115):
        sim.tick()
    s = sim.state()
    assert s["stats"]["compromised"] > 0, "attack produced no compromises"
    assert any(a["olt"] == "VTE" for a in s["alerts"]), "no zone alert for VTE"
    assert s["alerts"][0]["origin"] != "unknown", "alert missing origin province"
    assert s["top_ips"], "no attacker IPs tracked"
    n = sim.recover("VTE")
    assert n > 0 and sim.state()["stats"]["compromised"] == 0, "recovery failed"
    # statistics aggregation
    day, month, year = (sim.stats_range(r) for r in ("day", "month", "year"))
    assert len(day["labels"]) == 24 and len(month["labels"]) == 30 \
        and len(year["labels"]) == 12, "wrong bucket counts"
    assert sum(year["attacks"]) > 100, "backfilled history missing from year stats"
    assert year["by_zone"] and year["by_origin"], "zone/origin breakdown empty"
    # AI auto-approved recovery
    auto = Simulation(seed=7)
    auto.next_auto_attack = float("inf")
    auto.auto_recover = True
    auto.start_attack("LPB")
    for _ in range(120):
        auto.tick()
    s = auto.state()
    assert auto.recovered_total > 0, "AI auto-recovery never fired"
    assert s["stats"]["compromised"] == 0, "AI left compromised ONTs behind"
    assert any(e["kind"] == "ai" for e in auto.events), "no AI approval event logged"
    # live ingestion path
    live = Simulation(live=True)
    dev = next(iter(live.onts))
    live.ingest([{"device": dev, "type": "login_fail", "src_ip": "198.51.100.7"}] * 6)
    assert live.onts[dev]["status"] == "suspicious", "ingested fails not detected"
    live.ingest({"device": dev, "type": "cred_change", "src_ip": "198.51.100.7"})
    assert live.onts[dev]["status"] == "compromised", "ingested cred_change ignored"
    assert live.state()["top_ips"][0]["ip"] == "198.51.100.7", "src ip not aggregated"
    assert not live.history, "live mode must not backfill fake history"
    # HTTP auth gate
    import urllib.error
    import urllib.request
    global SIM
    SIM = Simulation(seed=1)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def req(path, data=None, tok=""):
        r = urllib.request.Request(base + path, data=data, headers={"X-Auth": tok})
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, None

    assert req("/api/state")[0] == 401, "state served without login"
    assert req("/api/login", b'{"user":"admin","pass":"wrong"}')[0] == 401, "bad creds accepted"
    code, j = req("/api/login", json.dumps({"user": AUTH_USER, "pass": AUTH_PASS}).encode())
    assert code == 200 and j["token"], "login failed"
    assert req("/api/state", tok=j["token"])[0] == 200, "token rejected"
    hb = json.dumps({"name": "pi-test", "site": "bench", "lat": 17.9, "lon": 102.6,
                     "cpu": 1.2, "ram": 34.0, "temp": 36.5, "recovered": 3}).encode()
    assert req("/api/sensor", hb, tok=j["token"])[0] == 200, "heartbeat rejected"
    sensors = req("/api/state", tok=j["token"])[1]["sensors"]
    assert sensors and sensors[0]["name"] == "pi-test" and sensors[0]["online"], \
        "sensor missing from state"
    srv.shutdown()
    print(f"self-check OK: provinces + stats + live ingestion + auth (recovered {n} ONTs)")


if __name__ == "__main__":
    if "--check" in sys.argv:
        check()
    else:
        port = (int(sys.argv[sys.argv.index("--port") + 1])
                if "--port" in sys.argv else 8000)
        run_server(port=port, live="--live" in sys.argv)
