# GeoAI FTTH Security Intelligence Platform — Simulation

Working simulation of the platform described in *GeoAI FTTH Security Intelligence Platform.docx*: detecting FTTH ONT account-takeover attacks in Vientiane, visualizing geographic hotspots, and batch-recovering compromised routers via a simulated ACS.

## Run

```bash
python3 simulator.py
```

Open http://localhost:8000. No dependencies — Python stdlib only; the dashboard uses Leaflet from CDN.

## Real-case monitoring

```bash
python3 simulator.py --live
```

`--live` disables all synthetic traffic — only ingested logs drive detection. Point your OLT/ACS/RADIUS log collectors at the ingestion API:

```bash
curl -X POST localhost:8000/api/log -d '{"device":"OLT-1-ONT-001","type":"login_fail","src_ip":"203.0.113.9"}'
```

Event types: `login_fail`, `cred_change`, `login_ok`. Send one event or a JSON array. The dashboard header shows **LIVE MONITORING**, and hostile source IPs are aggregated in the "Top attacker sources" panel.

To use your real ONT inventory, drop a `devices.csv` next to `simulator.py` (OLT zone positions are computed as the centroid of their ONTs):

```csv
id,olt,olt_name,lat,lon
OLT-1-ONT-001,OLT-1,Chanthabouly,17.9689,102.6137
```

Detection thresholds are constants at the top of `simulator.py` (`WINDOW`, `SUSPICIOUS_FAILS`, `ALERT_MIN_AFFECTED`) — tune them to your network's baseline.

Self-check (attack → detect → alert → recover):

```bash
python3 simulator.py --check
```

## What it simulates (mapped to the proposal)

| Doc component | Simulation |
|---|---|
| FTTH infrastructure | 18 province zones (all of Laos), ~260 ONTs |
| Auth log collection | Each ONT emits login-failure / credential-change events; attacker runs credential-stuffing sweeps per zone |
| AI detection | ≥5 failed logins per 60 s window → *suspicious*; attacker credential change → *compromised* |
| GeoAI hotspot analysis | Per-zone risk score (0–1) from compromised/suspicious ratio, drawn as colored risk rings on the map |
| Intelligent alerts & prioritization | Zone alerts with severity (low→critical), sorted by risk, with recommended action |
| Automated recovery (ACS) | One click batch-resets every affected ONT in a zone — or fully automatic with AI auto-approve |

Attacks auto-spawn every ~1–2 minutes from a random origin province, or trigger one manually with the ⚡ button.

## Login

The dashboard is gated by a sign-in screen. Default credentials: **admin / geoai2026** — change them via environment variables before starting:

```bash
GEOAI_USER=youruser GEOAI_PASS=yourpass python3 simulator.py
```

All `/api/*` endpoints require the session token (`X-Auth` header) issued by `POST /api/login` — including `/api/log`, so real log collectors must log in first and send the token.

## SOC interface

Three views in the sidebar menu:

- **Overview** — country-wide map of all 18 Laos provinces, ONT status markers, province risk rings, active attack path (origin → target, dashed red line), hotspot alerts with origin province, top attacker IPs, live event feed.
- **Analytics** — attack statistics with 24-hour / 30-day / 12-month range toggle: attacks-over-time chart, most-attacked provinces, attack-origin provinces. Demo mode seeds a year of synthetic history; live mode only accumulates real detections.
- **Events** — full event feed and attacker source list.

## Raspberry Pi edge sensor

[pi_agent.py](pi_agent.py) turns a Raspberry Pi into an edge monitor/sensor for the ONT server: it logs into the GeoAI API, polls the network state, detects hacked ONTs, performs the batch recovery itself, and every recovery it makes appears in the main GeoAI dashboard's live feed attributed to the sensor (`pi-sensor@<hostname>`). It serves its own monitor UI on port 8080 — server map, connection status, hack-simulation button, auto-recover toggle, and an action log.

```bash
./deploy_pi.sh                                  # deploy + start on the Pi
GEOAI_URL=http://server:port ./deploy_pi.sh     # point sensor elsewhere
```

Sensor config env vars: `GEOAI_URL`, `GEOAI_USER`, `GEOAI_PASS`, `PI_PORT`. Tip: turn OFF the dashboard's own "AI auto-approve recovery" toggle when demoing the Pi, so the recovery visibly comes from the device.

## GeoIP world attack map (Logstash + geoip-attack-map)

A global "see-overall" attack map ([attackmap/](attackmap/)) runs as a Docker stack on the CEIT server, separate from the dashboard: the real **[geoip-attack-map](https://github.com/MatthewClarkMay/geoip-attack-map)** project (DataServer + Norse-style world map) fed by real **Logstash**.

Pipeline: `simulator (attack events, real source IPs) → TCP → Logstash → syslog line → DataServer (GeoIP + aggregate) → Redis → MapServer (:8899) → browser`.

```bash
./deploy_attackmap.sh          # build + start the 3-container stack on CEIT
```

- **No credentials needed**: Logstash replaces the project's MaxMind-dependent input, and GeoIP uses a license-free GeoLite2 mirror (`attackmap/db/`, git-ignored, ~62 MB).
- The simulator ships each ONT takeover to Logstash only when `LOGSTASH_HOST` is set (deploy.sh sets it on CEIT); attacker source IPs are drawn from a real global pool so arcs originate from real countries.
- Adaptations for modern infra live in `attackmap/patch_*.py` and `mapserver.py`: Python-3 MapServer (upstream's `tornadoredis` is dead), keyless dark tiles (upstream's Mapbox token expired), relative `wss://` for the tunnel.

Expose it by pointing a Cloudflare tunnel hostname at `localhost:8899` on CEIT.

## API

- `GET /api/state` — full state (ONTs, zones, alerts, events, active attack path, stats)
- `GET /api/stats?range=day|month|year` — attack history aggregated for charts
- `POST /api/log` — ingest real auth events
- `POST /api/auto` — `{"enabled": true|false}` toggle AI auto-approved recovery (also a 🤖 toggle in the Overview sidebar); when on, batch recovery runs automatically once a zone has ≥`ALERT_MIN_AFFECTED` compromised ONTs
- `POST /api/attack` — launch a cross-province attack
- `POST /api/recover/<zone-id>` — batch-recover a zone
