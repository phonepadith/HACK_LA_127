#!/usr/bin/env python3
"""Patch the geoip-attack-map frontend for a keyless, tunnel-friendly deploy:
- swap the dead Mapbox base layer for keyless tiles + a CSS dark filter
- point the HQ marker + websocket at our host
- upgrade http:// CDN links to https:// (Cloudflare tunnel is https)
"""
import re
import sys

site = sys.argv[1]  # /app/repo/AttackMapServer
mapjs = site + "/static/map.js"
index = site + "/index.html"

# --- map.js -----------------------------------------------------------------
js = open(mapjs).read()

# drop the mapbox token line
js = re.sub(r'L\.mapbox\.accessToken\s*=\s*".*?";', "", js)

# replace the L.mapbox.map(...) init (through its closing "});") with plain Leaflet
js = re.sub(
    r'var map = L\.mapbox\.map\("map",\s*"mapbox\.dark",\s*\{.*?\}\);',
    'var map = L.map("map", {center: [20, 20], zoom: 2, worldCopyJump: true});\n'
    'L.tileLayer("https://mt{s}.google.com/vt/lyrs=m&x={x}&y={y}&z={z}", '
    '{subdomains: "0123", maxZoom: 18}).addTo(map);',
    js, flags=re.S)

# HQ marker -> Laos (matches the arc destinations set by DataServer HQ_IP)
js = js.replace("new L.LatLng(37.3845, -122.0881)", "new L.LatLng(17.9641, 102.5987)")

# websocket -> same host/scheme the page was served from
js = js.replace('new WebSocket("ws:/127.0.0.1:8888/websocket")',
                'new WebSocket((location.protocol==="https:"?"wss://":"ws://")'
                '+location.host+"/websocket")')

open(mapjs, "w").write(js)

# --- index.html -------------------------------------------------------------
html = open(index).read()
html = html.replace("http://d3js.org", "https://d3js.org")
html = html.replace("http://cdn.leafletjs.com", "https://cdn.leafletjs.com")
# dark-filter the (light) Google tiles, matching the rest of the platform
html = html.replace("</head>",
    "<style>.leaflet-tile-pane{filter:invert(92%) hue-rotate(180deg) "
    "brightness(.9) contrast(.92) saturate(.55)}</style></head>")
open(index, "w").write(html)
print("patched frontend")
