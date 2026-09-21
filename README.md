# GeoAI FTTH Security Intelligence Platform — Simulation

Working simulation of the platform described in *GeoAI FTTH Security Intelligence Platform.docx*: detecting FTTH ONT account-takeover attacks in Vientiane, visualizing geographic hotspots, and batch-recovering compromised routers via a simulated ACS.

## Architecture

![System architecture](https://raw.githubusercontent.com/phonepadith/geoai-security/main/docs/architecture.png)

Editable source: [docs/architecture.drawio](docs/architecture.drawio) (open at [app.diagrams.net](https://app.diagrams.net)) — generated from [docs/architecture.ir.json](docs/architecture.ir.json).

## Software stack

Two deliberate constraints shape the implementation: the SOC core runs on **Python 3 standard
library only** — no pip install, no venv, no build step, so it starts on any box that has
`python3` — and everything heavier (GeoIP enrichment, search, analytics) is pushed into a
separate Docker stack that can be switched off without touching detection.

**SOC core** — `simulator.py`, CEIT server, port 3030 (8000 default)

| | |
|---|---|
| Runtime | Python 3, stdlib only: `http.server.ThreadingHTTPServer`, `json`, `csv`, `secrets`, `threading`, `urllib.request` |
| State | In-process memory — ONT inventory, zone risk, alerts, 60-event ring buffer, attack history |
| Auth | Single shared login, `secrets.token_hex` session tokens, `X-Auth` header on every `/api/*` |
| Detection | ≥5 failed logins / 60 s → suspicious; credential change → compromised (constants at the top of the file) |
| Recovery | ACS batch reset per zone — stubbed; wire a vendor TR-069/NETCONF call in `_do_recover()` |

**Dashboard** — `dashboard.html`, one file, no bundler

| | |
|---|---|
| UI | Vanilla JS + CSS custom properties, no framework |
| Map (2D) | [Leaflet](https://leafletjs.com) 1.9.4 (unpkg), Google raster tiles |
| Map (3D) | [MapLibre GL](https://maplibre.org) 5.6.1, lazy-loaded — CARTO dark vector basemap + AWS terrarium elevation tiles, both keyless |
| Charts | [ApexCharts](https://apexcharts.com) (jsDelivr) |
| Type | IBM Plex Sans / Mono (Google Fonts) |
| Data | Polls `GET /api/state` every 3 s; `GET /api/stats?range=` for the analytics view |

**AI analyst** — see [AI analyst (SEA-LION)](#ai-analyst-sea-lion)

| | |
|---|---|
| Model | `aisingapore/Gemma-SEA-LION-v4-27B-IT` (configurable) |
| Transport | OpenAI-compatible REST over `urllib.request` — no SDK |
| Boundary | Key server-side only; the browser calls `POST /api/analyze` behind the session token |

**Edge sensor** — `pi_agent.py`, Raspberry Pi

| | |
|---|---|
| Runtime | Python 3 stdlib; own monitor UI on port 8080 |
| Service | systemd unit [`geoai-sensor.service`](geoai-sensor.service), `Restart=always` |
| Behaviour | Polls the GeoAI API every 3 s, detects compromised ONTs, performs its own batch recovery, heartbeats to `POST /api/sensor` |

**Attack-map + analytics stack** — `attackmap/`, Docker Compose, five containers

| Container | Image | Role |
|---|---|---|
| `logstash` | `logstash:8.15.0` | TCP :5055 `json_lines` in → `geoip` filter → CSV syslog line + Elasticsearch out |
| `elasticsearch` | `elasticsearch:8.15.0` | Single-node, security disabled, `geoai-attacks-*` indices, bound to 127.0.0.1 |
| `kibana` | `kibana:8.15.0` | Port 5601; index template, data view and TSVB dashboard provisioned by `setup_kibana.py` |
| `redis` | `redis:7-alpine` | Pub/sub between DataServer and MapServer |
| `attackmap` | `python:3.11-slim` + tornado, redis, maxminddb | Upstream [geoip-attack-map](https://github.com/MatthewClarkMay/geoip-attack-map) cloned at build; `mapserver.py` replaces its dead `tornadoredis` server; port 8899 |

GeoIP data is MaxMind **GeoLite2-City** from a license-free mirror (`attackmap/db/`, git-ignored,
~62 MB) — no MaxMind account needed. Frontend patches for modern infra live in
`attackmap/patch_*.py`.

**Exposure and deployment**

| | |
|---|---|
| Ingress | Cloudflare tunnel → `geoai-ftth-demo`, `attackmap`, `kibana-dashboard` `.laopadit.com` |
| Deploy | `deploy.sh` (tar over SSH, restart), `deploy_attackmap.sh` (compose build + Kibana provisioning), `deploy_pi.sh` — no CI |
| Secrets | Environment variables; `.env` is git-ignored and forwarded by `deploy.sh` |
| Install agent | [`agent/`](agent/) — LangGraph ReAct agent on OpenAI, fixed-template SSH tools, dry-run by default; the only component with third-party deps |
| Data export | `export_stats.py` → [`data/*.csv`](data/) — attack timeseries, per-zone totals, live zone status, attacker IPs |
| Tests | `python3 simulator.py --check` — attack → detect → alert → recover, stats, live ingestion, auth gate, AI brief |

## Screenshots

| | |
|---|---|
| ![Sign-in](https://raw.githubusercontent.com/phonepadith/geoai-security/main/docs/screenshots/01-login.png) **Sign-in** | ![Overview](https://raw.githubusercontent.com/phonepadith/geoai-security/main/docs/screenshots/02-overview.png) **Overview** — Laos map, ONT status, risk rings, Pi edge sensor |
| ![Analytics](https://raw.githubusercontent.com/phonepadith/geoai-security/main/docs/screenshots/03-analytics.png) **Analytics** — attacks over time, target/origin provinces | ![Events](https://raw.githubusercontent.com/phonepadith/geoai-security/main/docs/screenshots/04-events.png) **Events** — full feed + top attacker sources |

![Kibana](https://raw.githubusercontent.com/phonepadith/geoai-security/main/docs/screenshots/05-kibana.png)
*Kibana — GeoAI Attack Analytics dashboard (attack source map, counters, histogram)*

![World attack map](https://raw.githubusercontent.com/phonepadith/geoai-security/main/docs/screenshots/06-world-attack-map.png)
*GeoIP world attack map — Norse-style live arcs, per-service/country/IP counters, exploit feed*

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

The Overview map has a **2D / 3D** toggle. 3D renders the same ONT markers, province risk
rings and attack paths on tilted terrain (MapLibre GL + elevation data), with drag to rotate
and ctrl+drag to tilt. MapLibre is fetched only when 3D is first pressed, so the default 2D
view costs nothing; the view centre carries across when you switch.

## AI analyst (SEA-LION)

The Overview sidebar has a **🧠 AI analyst** panel backed by [SEA-LION](https://sea-lion.ai)
(AI Singapore's SEA-focused LLM). It writes a short shift report on the live case, or answers
a typed question about it — which zone to recover first, whether an attack is still running,
which source IP dominates.

The server builds a compact brief of the current state (stats, zone alerts ranked worst-first,
attacker IPs, edge sensors, last 15 events) and sends only that. The browser never sees the API
key; every call goes through `POST /api/analyze`, behind the same session token as the rest of
`/api/*`.

```bash
export SEALION_API_KEY=sk-...          # or put it in .env (git-ignored)
python3 simulator.py
```

| Variable | Default | |
|---|---|---|
| `SEALION_API_KEY` | *(unset)* | Required — without it `/api/analyze` returns 502 and the panel says so |
| `SEALION_MODEL` | `aisingapore/Gemma-SEA-LION-v4-27B-IT` | Any chat model from `GET https://api.sea-lion.ai/v1/models` |
| `SEALION_URL` | `https://api.sea-lion.ai/v1/chat/completions` | OpenAI-compatible endpoint |

`deploy.sh` reads `.env` and forwards the key to the server. Stdlib only — the call uses
`urllib.request`, no SDK.

The prompt pins the model to the supplied state ("never invent devices, IPs or numbers";
recommendations limited to ACS batch reset, threshold tuning, or blocking a source IP), and
the state is labelled as data rather than instructions. It is decision support, not an
autonomous actor — it cannot trigger recovery; only the operator or the auto-approve toggle can.

## Raspberry Pi edge sensor

New nodes can be provisioned by an **[agentic installer](agent/)** (LangGraph + OpenAI):
it checks the host, ships the agent, installs the systemd unit, and confirms the sensor
actually registers with the server before calling the install done.

```bash
python3 agent/install_sensor_agent.py --host kobi@192.168.0.110 --zone LPB          # dry run
python3 agent/install_sensor_agent.py --host kobi@192.168.0.110 --zone LPB --apply  # install
```


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

### Elasticsearch + Kibana (T-Pot-style analytics)

The same stack also runs **Elasticsearch + Kibana**: Logstash indexes every geoip-enriched attack into `geoai-attacks-*`, and `attackmap/setup_kibana.py` provisions the index template, data view, and a **GeoAI — Attack Analytics** dashboard (TSVB panels: total/unique/countries counters, attacks-over-time histogram, top attacker countries / services / reputation / source IPs / destination ports). `deploy_attackmap.sh` runs the provisioning automatically. Kibana is on `localhost:5601` — tunnel a subdomain to reach it. ES runs single-node with security disabled (internal-only, behind the tunnel).

## API

- `GET /api/state` — full state (ONTs, zones, alerts, events, active attack path, stats)
- `GET /api/stats?range=day|month|year` — attack history aggregated for charts
- `POST /api/log` — ingest real auth events
- `POST /api/auto` — `{"enabled": true|false}` toggle AI auto-approved recovery (also a 🤖 toggle in the Overview sidebar); when on, batch recovery runs automatically once a zone has ≥`ALERT_MIN_AFFECTED` compromised ONTs
- `POST /api/attack` — launch a cross-province attack
- `POST /api/recover/<zone-id>` — batch-recover a zone
- `POST /api/analyze` — `{"q": "..."}` ask SEA-LION about the live case (omit `q` for the shift report)
