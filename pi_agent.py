#!/usr/bin/env python3
"""GeoAI edge sensor agent — runs on a Raspberry Pi next to the FTTH plant.

Connects to the (mock) ONT server, watches for hacked ONTs, performs the
batch recovery itself, and reports every action back to the main GeoAI
dashboard (recoveries appear in its live feed attributed to this sensor).
Serves its own monitor interface with the server map on port 8080.

Config (env):
  GEOAI_URL   ONT/GeoAI server (default http://192.168.0.111:8000)
  GEOAI_USER / GEOAI_PASS   server login (default admin/geoai2026)
  PI_PORT     local UI port (default 8080)

Run:        python3 pi_agent.py
Self-check: python3 pi_agent.py --check
"""
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GEOAI_URL = os.environ.get("GEOAI_URL", "http://192.168.0.111:8000").rstrip("/")
GEOAI_USER = os.environ.get("GEOAI_USER", "admin")
GEOAI_PASS = os.environ.get("GEOAI_PASS", "geoai2026")
PI_PORT = int(os.environ.get("PI_PORT", "8080"))
POLL_SECONDS = 3
NAME = "pi-sensor@" + socket.gethostname()
# physical install location of this sensor (default: Vientiane riverside site)
SENSOR_LAT = float(os.environ.get("SENSOR_LAT", "17.8677045"))
SENSOR_LON = float(os.environ.get("SENSOR_LON", "102.6169395"))
SENSOR_SITE = os.environ.get("SENSOR_SITE", "Vientiane riverside site")
SENSOR_ZONE = os.environ.get("SENSOR_ZONE", "VTE")  # zone this sensor guards


_prev_cpu = None


def system_stats():
    """CPU %, RAM %, and SoC temperature from /proc and /sys (Linux only)."""
    global _prev_cpu
    stats = {}
    try:
        vals = list(map(int, open("/proc/stat").readline().split()[1:]))
        total, idle = sum(vals), vals[3] + vals[4]
        if _prev_cpu:
            dt, di = total - _prev_cpu[0], idle - _prev_cpu[1]
            stats["cpu"] = round(100 * (1 - di / dt), 1) if dt else 0.0
        _prev_cpu = (total, idle)
    except (OSError, ValueError, IndexError):
        pass
    try:
        mem = {}
        for line in open("/proc/meminfo"):
            k, v = line.split(":")
            mem[k] = int(v.split()[0])
        stats["ram"] = round(100 * (1 - mem["MemAvailable"] / mem["MemTotal"]), 1)
        stats["ram_used_mb"] = (mem["MemTotal"] - mem["MemAvailable"]) // 1024
        stats["ram_total_mb"] = mem["MemTotal"] // 1024
    except (OSError, ValueError, KeyError):
        pass
    try:
        stats["temp"] = round(int(open("/sys/class/thermal/thermal_zone0/temp").read()) / 1000, 1)
    except (OSError, ValueError):
        pass
    return stats


def zones_to_recover(state):
    """Zones with at least one hacked ONT, from a GeoAI /api/state payload."""
    zones = {}
    for o in state.get("onts", []):
        if o.get("status") == "compromised":
            zones[o["olt"]] = zones.get(o["olt"], 0) + 1
    return sorted(zones)


class Agent:
    def __init__(self):
        self.token = None
        self.connected = False
        self.state = None
        self.last_poll = "never"
        self.auto = True
        self.recovered = 0
        self.attacked = False
        self.sys = {}
        self.events = []
        self.lock = threading.Lock()
        self.log(f"edge sensor {NAME} starting — target {GEOAI_URL}")

    def log(self, msg):
        with self.lock:
            self.events.append({"t": time.strftime("%H:%M:%S"), "msg": msg})
            del self.events[:-60]

    def _req(self, path, data=None, auth=True):
        # identify ourselves: Cloudflare blocks the default Python-urllib agent
        headers = {"User-Agent": "GeoAI-EdgeSensor/1.0"}
        if auth:
            headers["X-Auth"] = self.token or ""
        r = urllib.request.Request(GEOAI_URL + path, data=data, headers=headers)
        with urllib.request.urlopen(r, timeout=6) as resp:
            return json.loads(resp.read())

    def login(self):
        j = self._req("/api/login", auth=False,
                      data=json.dumps({"user": GEOAI_USER, "pass": GEOAI_PASS}).encode())
        self.token = j["token"]
        self.log("authenticated to ONT server")

    def recover(self, zone, reason="hack detected"):
        j = self._req(f"/api/recover/{zone}?by={NAME}", data=b"")
        n = j.get("reset", 0)
        self.recovered += n
        self.log(f"RECOVERY: reset {n} ONTs in {zone} ({reason}) — reported to GeoAI dashboard")
        return n

    def attack(self):
        self._req("/api/attack", data=json.dumps({"zone": SENSOR_ZONE}).encode())
        self.log(f"hack simulation requested on this sensor's zone ({SENSOR_ZONE})")

    def poll(self):
        try:
            if not self.token:
                self.login()
            s = self._req("/api/state")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                self.token = None  # session expired (server restart) — re-login next poll
                return
            self.connected = False
            return
        except OSError:
            if self.connected:
                self.log("lost connection to ONT server")
            self.connected = False
            return
        if not self.connected:
            self.connected = True
            self.log(f"connected to ONT server ({s['stats']['total']} ONTs, "
                     f"{len(s['olts'])} zones)")
        self.state = s
        self.last_poll = time.strftime("%H:%M:%S")
        was = self.attacked
        self.attacked = (any(o["status"] != "normal" and o["olt"] == SENSOR_ZONE
                             for o in s.get("onts", []))
                         or (s.get("attack") or {}).get("zone") == SENSOR_ZONE)
        if self.attacked and not was:
            self.log(f"⚠ ATTACK on this sensor's zone ({SENSOR_ZONE}) detected")
        try:  # heartbeat: report status so the main dashboard shows this sensor
            self._req("/api/sensor", data=json.dumps({
                "name": NAME, "site": SENSOR_SITE, "zone": SENSOR_ZONE,
                "lat": SENSOR_LAT, "lon": SENSOR_LON,
                "recovered": self.recovered, **self.sys}).encode())
        except OSError:
            pass
        if self.auto:
            for zone in zones_to_recover(s):
                try:
                    self.recover(zone)
                except OSError:
                    pass

    def snapshot(self):
        with self.lock:
            return {
                "name": NAME, "server": GEOAI_URL, "connected": self.connected,
                "location": {"lat": SENSOR_LAT, "lon": SENSOR_LON},
                "zone": SENSOR_ZONE, "attacked": self.attacked,
                "sys": self.sys,
                "last_poll": self.last_poll, "auto": self.auto,
                "recovered": self.recovered, "events": self.events[::-1],
                "state": self.state,
            }


AGENT = None

UI = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>GeoAI Edge Sensor</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
:root{--bg:#0A1220;--panel:#0F1B2D;--border:rgba(255,255,255,.08);--text:#EAF4FF;
--dim:#8CA3BD;--ok:#34D399;--warn:#FFA857;--bad:#FB5B6E;--accent:#22D3EE}
*{box-sizing:border-box;margin:0}
body{font:13px/1.45 'IBM Plex Sans',-apple-system,sans-serif;background:var(--bg);
color:var(--text);height:100vh;display:flex;flex-direction:column;overflow:hidden}
header{display:flex;align-items:center;gap:14px;background:var(--panel);
border-bottom:1px solid var(--border);padding:10px 16px;flex-wrap:wrap}
header b{font-family:'IBM Plex Mono',monospace;color:var(--accent);letter-spacing:.1em}
.chip{font-size:11px;color:var(--dim);border:1px solid var(--border);border-radius:20px;
padding:3px 10px}
#conn.on{color:var(--ok);border-color:var(--ok)}
#conn.off{color:var(--bad);border-color:var(--bad)}
main{flex:1;display:flex;min-height:0}
#map{flex:1;background:var(--bg)}
.leaflet-tile-pane{filter:invert(92%) hue-rotate(180deg) brightness(.9) contrast(.92)
saturate(.55)}
aside{width:340px;border-left:1px solid var(--border);background:var(--panel);
overflow-y:auto;padding:12px 14px}
aside h2{font-size:11px;text-transform:uppercase;color:var(--dim);letter-spacing:.05em;
margin:10px 0 6px}
button{background:#12203A;border:1px solid var(--border);border-radius:6px;
color:var(--text);padding:7px 10px;cursor:pointer;font-size:12px;width:100%;margin:3px 0}
#atk{color:var(--bad)} #atk:hover{border-color:var(--bad)}
label{display:flex;gap:8px;align-items:center;font-size:12px;margin:6px 0}
.log div{padding:2px 0;color:var(--dim);font:11px 'IBM Plex Mono',monospace}
.log .rec{color:var(--ok)}
.sensor-box{width:20px;height:20px;background:var(--panel);border:2px solid var(--accent);
border-radius:5px;box-shadow:0 0 10px rgba(34,211,238,.65);display:flex;align-items:center;
justify-content:center}
.sensor-box i{width:6px;height:6px;border-radius:50%;background:var(--ok);
animation:led 1.2s infinite}
.sensor-box.atk{border-color:var(--bad);box-shadow:0 0 14px rgba(251,91,110,.9)}
.sensor-box.atk i{background:var(--bad);animation:led .4s infinite}
#atkchip{display:none;color:var(--bad);border-color:var(--bad);font-weight:700;
animation:led 1s infinite}
@keyframes led{50%{opacity:.15}}
@media(max-width:768px){main{flex-direction:column}#map{flex:none;height:45vh}
aside{width:100%;border-left:0;border-top:1px solid var(--border)}}
</style></head><body>
<header>
  <b>⬢ GEOAI · EDGE SENSOR</b>
  <span class="chip" id="dev">…</span>
  <span class="chip">ONT server: <span id="srv">…</span></span>
  <span class="chip" id="conn">connecting…</span>
  <span class="chip">last poll <span id="poll">–</span></span>
  <span class="chip" style="color:var(--ok)"><span id="rec">0</span> ONTs recovered</span>
  <span class="chip">CPU <span id="cpu">–</span></span>
  <span class="chip">RAM <span id="ram">–</span></span>
  <span class="chip" id="tempchip" style="display:none">🌡 <span id="temp">–</span></span>
  <span class="chip">zone <span id="zone">–</span></span>
  <span class="chip" id="atkchip">⚠ ZONE UNDER ATTACK</span>
</header>
<main>
  <div id="map"></div>
  <aside>
    <h2>Sensor controls</h2>
    <label><input type="checkbox" id="auto" checked> Auto-recover hacked ONTs</label>
    <button id="atk">⚡ Simulate hack on this sensor's zone</button>
    <h2>Sensor action log</h2>
    <div class="log" id="log"></div>
  </aside>
</main>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const map = L.map('map').setView([18.4, 103.5], 6);
L.tileLayer('https://mt{s}.google.com/vt/lyrs=m&x={x}&y={y}&z={z}',
  {subdomains: '0123', attribution: '&copy; Google', maxZoom: 20}).addTo(map);
const C = {normal:'#34D399', suspicious:'#FFA857', compromised:'#FB5B6E'};
const onts = {}, zones = {};
let sensorPin = null;
document.getElementById('atk').onclick = () => fetch('/pi/attack', {method:'POST'});
document.getElementById('auto').onchange = e =>
  fetch('/pi/auto', {method:'POST', body: JSON.stringify({enabled: e.target.checked})});
async function tick() {
  let d;
  try { d = await (await fetch('/pi/state')).json(); } catch { return; }
  document.getElementById('dev').textContent = d.name;
  document.getElementById('srv').textContent = d.server;
  document.getElementById('poll').textContent = d.last_poll;
  document.getElementById('rec').textContent = d.recovered;
  document.getElementById('cpu').textContent = d.sys.cpu != null ? d.sys.cpu + '%' : 'n/a';
  document.getElementById('ram').textContent = d.sys.ram != null
    ? `${d.sys.ram}% (${d.sys.ram_used_mb}/${d.sys.ram_total_mb} MB)` : 'n/a';
  if (d.sys.temp != null) {
    document.getElementById('tempchip').style.display = '';
    document.getElementById('temp').textContent = d.sys.temp + '°C';
  }
  document.getElementById('zone').textContent = d.zone;
  document.getElementById('atkchip').style.display = d.attacked ? '' : 'none';
  document.querySelector('.sensor-box')?.classList.toggle('atk', !!d.attacked);
  const conn = document.getElementById('conn');
  conn.textContent = d.connected ? '● connected' : '● offline';
  conn.className = 'chip ' + (d.connected ? 'on' : 'off');
  if (!sensorPin && d.location) {
    sensorPin = L.marker([d.location.lat, d.location.lon], {icon: L.divIcon(
      {className: '', html: '<div class="sensor-box"><i></i></div>', iconSize: [24, 24],
       iconAnchor: [12, 12]}), zIndexOffset: 1000})
      .bindTooltip(`${d.name} — edge sensor site<br>${d.location.lat.toFixed(5)}, ` +
                   d.location.lon.toFixed(5), {direction: 'top'}).addTo(map);
  }
  document.getElementById('log').innerHTML = d.events.map(e =>
    `<div class="${e.msg.startsWith('RECOVERY') ? 'rec' : ''}">[${e.t}] ${e.msg}</div>`).join('');
  if (!d.state) return;
  for (const o of d.state.onts) {
    if (!onts[o.id]) onts[o.id] = L.circleMarker([o.lat, o.lon],
      {radius: 4.5, weight: 1}).bindTooltip(o.id).addTo(map);
    onts[o.id].setStyle({color: C[o.status], fillColor: C[o.status],
      fillOpacity: o.status === 'normal' ? .5 : .9});
  }
  for (const z of d.state.olts) {
    if (!zones[z.id]) zones[z.id] = L.circle([z.lat, z.lon],
      {radius: 11000, weight: 1.5, fillOpacity: .05})
      .bindTooltip(`${z.name} (${z.id})`).addTo(map);
    const c = z.risk > .5 ? '#FB5B6E' : z.risk > .2 ? '#FFA857' : '#22D3EE';
    zones[z.id].setStyle({color: c, fillColor: c, fillOpacity: .04 + z.risk * .25});
  }
}
tick(); setInterval(tick, 2000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(UI.encode(), "text/html; charset=utf-8")
        elif self.path == "/pi/state":
            self._send(AGENT.snapshot())
        else:
            self.send_error(404)

    def do_POST(self):
        try:
            if self.path == "/pi/attack":
                AGENT.attack()
                self._send({"ok": True})
            elif self.path == "/pi/auto":
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                AGENT.auto = bool(body.get("enabled"))
                AGENT.log(f"auto-recovery {'enabled' if AGENT.auto else 'disabled'}")
                self._send({"ok": True, "auto": AGENT.auto})
            elif self.path.startswith("/pi/recover/"):
                self._send({"ok": True,
                            "reset": AGENT.recover(self.path.rsplit("/", 1)[1], "manual")})
            else:
                self.send_error(404)
        except OSError:
            self.send_error(502, "ONT server unreachable")

    def log_message(self, *a):
        pass


def main():
    global AGENT
    AGENT = Agent()

    def loop():
        while True:
            AGENT.sys = system_stats()
            AGENT.poll()
            time.sleep(POLL_SECONDS)
    threading.Thread(target=loop, daemon=True).start()
    print(f"GeoAI edge sensor UI on http://0.0.0.0:{PI_PORT} — watching {GEOAI_URL}")
    ThreadingHTTPServer(("", PI_PORT), Handler).serve_forever()


def check():
    state = {"onts": [
        {"id": "A-1", "olt": "VTE", "status": "compromised"},
        {"id": "A-2", "olt": "VTE", "status": "normal"},
        {"id": "B-1", "olt": "LPB", "status": "suspicious"},
        {"id": "C-1", "olt": "XKH", "status": "compromised"},
    ]}
    assert zones_to_recover(state) == ["VTE", "XKH"], "wrong zones flagged"
    assert zones_to_recover({"onts": []}) == [], "empty state should flag nothing"
    s1 = system_stats(); time.sleep(0.2); s2 = system_stats()
    assert isinstance(s2, dict), "system_stats must return a dict"
    if os.path.exists("/proc/stat"):  # Linux: values must actually be present
        assert "cpu" in s2 and "ram" in s2, "cpu/ram missing on Linux"
    print("self-check OK: hacked-zone detection + system stats", s2 or "(non-Linux)")


if __name__ == "__main__":
    check() if "--check" in sys.argv else main()
