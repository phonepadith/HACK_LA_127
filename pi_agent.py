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
        self.events = []
        self.lock = threading.Lock()
        self.log(f"edge sensor {NAME} starting — target {GEOAI_URL}")

    def log(self, msg):
        with self.lock:
            self.events.append({"t": time.strftime("%H:%M:%S"), "msg": msg})
            del self.events[:-60]

    def _req(self, path, data=None, auth=True):
        headers = {"X-Auth": self.token or ""} if auth else {}
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
        self._req("/api/attack", data=b"")
        self.log("hack simulation requested on ONT server")

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
#map{flex:1}
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
</header>
<main>
  <div id="map"></div>
  <aside>
    <h2>Sensor controls</h2>
    <label><input type="checkbox" id="auto" checked> Auto-recover hacked ONTs</label>
    <button id="atk">⚡ Simulate ONT hack on server</button>
    <h2>Sensor action log</h2>
    <div class="log" id="log"></div>
  </aside>
</main>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const map = L.map('map').setView([18.4, 103.5], 6);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
  {attribution: '&copy; OpenStreetMap &copy; CARTO', maxZoom: 18}).addTo(map);
const C = {normal:'#34D399', suspicious:'#FFA857', compromised:'#FB5B6E'};
const onts = {}, zones = {};
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
  const conn = document.getElementById('conn');
  conn.textContent = d.connected ? '● connected' : '● offline';
  conn.className = 'chip ' + (d.connected ? 'on' : 'off');
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
    print("self-check OK: hacked-zone detection")


if __name__ == "__main__":
    check() if "--check" in sys.argv else main()
