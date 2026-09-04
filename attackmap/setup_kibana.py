#!/usr/bin/env python3
"""Provision the Elasticsearch index template, Kibana data view, and a
T-Pot-style attack dashboard. Runs on the CEIT host after `docker compose up`
(ES on localhost:9200, Kibana on localhost:5601). Idempotent (overwrite=true)."""
import json
import time
import urllib.error
import urllib.request

ES = "http://localhost:9200"
KB = "http://localhost:5601"
IDX = "geoai-attacks"
DV_ID = "geoai-attacks-dv"


def req(url, data=None, method=None, headers=None, raw=False):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    body = data if raw else (json.dumps(data).encode() if data is not None else None)
    r = urllib.request.Request(url, data=body, method=method, headers=h)
    with urllib.request.urlopen(r, timeout=30) as resp:
        return resp.status, resp.read()


def wait(url, label, tries=90):
    for _ in range(tries):
        try:
            req(url)
            print(f"[*] {label} ready")
            return
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            time.sleep(4)
    raise SystemExit(f"[!] {label} never became ready")


# --- 1. Elasticsearch index template (geoip.location must be geo_point) ------
wait(ES, "Elasticsearch")
req(f"{ES}/_index_template/geoai-attacks", method="PUT", data={
    "index_patterns": ["geoai-attacks-*"],
    "template": {"mappings": {"properties": {
        "geoip": {"properties": {"location": {"type": "geo_point"}}}}}},
})
print("[*] index template installed")

# --- 2. Kibana data view -----------------------------------------------------
wait(f"{KB}/api/status", "Kibana")
XSRF = {"kbn-xsrf": "true"}
try:
    req(f"{KB}/api/data_views/data_view", method="POST", headers=XSRF, data={
        "data_view": {"id": DV_ID, "title": "geoai-attacks-*", "timeFieldName": "@timestamp"}})
    print("[*] data view created")
except urllib.error.HTTPError as e:
    print("[*] data view exists" if e.code == 409 else f"[!] data view: {e.code}")

# --- 3. Saved objects: TSVB visualizations + dashboard -----------------------
# Every panel is a TSVB ("metrics") visualization — reliable in Kibana 8.x and
# self-contained (embeds the index_pattern string, no index-pattern reference).
IP = "geoai-attacks-*"


def viz(oid, params):
    params["id"] = oid
    params["index_pattern"] = IP
    params["time_field"] = "@timestamp"
    state = {"title": params.pop("_title"), "type": "metrics", "aggs": [], "params": params}
    return {"id": oid, "type": "visualization",
            "attributes": {"title": state["title"], "visState": json.dumps(state),
                           "uiStateJSON": "{}", "description": "", "version": 1,
                           "kibanaSavedObjectMeta": {"searchSourceJSON":
                               '{"query":{"query":"","language":"kuery"},"filter":[]}'}},
            "references": []}


def metric(oid, title, mtype, field=None, color="#22D3EE"):
    m = {"id": "m1", "type": mtype}
    if field:
        m["field"] = field
    return viz(oid, {"_title": title, "type": "metric", "series": [
        {"id": "s1", "split_mode": "everything", "color": color, "label": title,
         "metrics": [m]}]})


def topn(oid, title, field, color="#22D3EE"):
    return viz(oid, {"_title": title, "type": "top_n", "bar_color_rules": [
        {"id": "r1", "value": 0, "bar_color": color, "opperator": "gte"}], "series": [
        {"id": "s1", "split_mode": "terms", "terms_field": field, "terms_size": "10",
         "color": color, "metrics": [{"id": "m1", "type": "count"}]}]})


def timeseries(oid, title):
    return viz(oid, {"_title": title, "type": "timeseries", "interval": "auto",
        "axis_position": "left", "show_legend": 1, "show_grid": 1, "series": [
        {"id": "s1", "label": "Attacks", "chart_type": "bar", "fill": "0.8",
         "stacked": "none", "line_width": 1, "split_mode": "everything", "color": "#22D3EE",
         "metrics": [{"id": "m1", "type": "count"}]},
        {"id": "s2", "label": "Unique source IPs", "chart_type": "line", "fill": "0",
         "stacked": "none", "line_width": 2, "split_mode": "everything", "color": "#FB5B6E",
         "metrics": [{"id": "m2", "type": "cardinality", "field": "src_ip.keyword"}]}]})


def geomap(oid, title):
    """Kibana Maps bubble map: attack sources over geoip.location, sized by count."""
    layers = [
        # keyless OSM raster base (the Elastic Maps Service is unreachable here)
        {"id": "basemap", "label": "OpenStreetMap", "minZoom": 0, "maxZoom": 19, "alpha": 1,
         "sourceDescriptor": {"type": "EMS_XYZ", "id": "osm",
                              "urlTemplate": "https://tile.openstreetmap.org/{z}/{x}/{y}.png"},
         "visible": True, "style": {"type": "RASTER"}, "type": "RASTER_TILE"},
        {"id": "clusters", "label": "Attack sources", "minZoom": 0, "maxZoom": 24,
         "alpha": 0.85, "visible": True, "type": "GEOJSON_VECTOR", "joins": [],
         "sourceDescriptor": {
             "type": "ES_GEO_GRID", "resolution": "COARSE", "id": "grid1",
             "geoField": "geoip.location", "requestType": "point",
             "metrics": [{"type": "count", "label": "Attacks"}],
             "indexPatternRefName": "layer_1_source_index_pattern",
             "applyGlobalQuery": True, "applyGlobalTime": True},
         "style": {"type": "VECTOR", "isTimeAware": True, "properties": {
             "icon": {"type": "STATIC", "options": {"value": "marker"}},
             "fillColor": {"type": "STATIC", "options": {"color": "#FB5B6E"}},
             "lineColor": {"type": "STATIC", "options": {"color": "#FFFFFF"}},
             "lineWidth": {"type": "STATIC", "options": {"size": 1}},
             "iconSize": {"type": "DYNAMIC", "options": {
                 "minSize": 6, "maxSize": 40,
                 "field": {"name": "doc_count", "origin": "source"},
                 "fieldMetaOptions": {"isEnabled": True, "sigma": 3}}},
             "labelText": {"type": "DYNAMIC", "options": {
                 "field": {"name": "doc_count", "origin": "source"}}},
             "labelColor": {"type": "STATIC", "options": {"color": "#FFFFFF"}},
             "labelSize": {"type": "STATIC", "options": {"size": 12}},
             "labelBorderColor": {"type": "STATIC", "options": {"color": "#000000"}},
             "labelBorderSize": {"options": {"size": "SMALL"}}}}}]
    state = {"zoom": 1.7, "center": {"lon": 40, "lat": 20},
             "timeFilters": {"from": "now-24h", "to": "now"},
             "query": {"query": "", "language": "kuery"}, "filters": []}
    return {"id": oid, "type": "map", "attributes": {
        "title": title, "description": "Attack sources (GeoIP)",
        "mapStateJSON": json.dumps(state), "layerListJSON": json.dumps(layers),
        "uiStateJSON": "{}"},
        "references": [{"name": "layer_1_source_index_pattern",
                        "type": "index-pattern", "id": DV_ID}]}


objs = [
    {"id": DV_ID, "type": "index-pattern",
     "attributes": {"title": "geoai-attacks-*", "timeFieldName": "@timestamp"},
     "references": []},
    geomap("g-map", "Attack Source Map"),
    metric("g-total", "Total Attacks", "count"),
    metric("g-ips", "Unique Source IPs", "cardinality", "src_ip.keyword", "#FFA857"),
    metric("g-countries", "Source Countries", "cardinality",
           "geoip.country_name.keyword", "#34D399"),
    timeseries("g-time", "Attacks over time"),
    topn("g-country", "Top Attacker Countries", "geoip.country_name.keyword", "#FB5B6E"),
    topn("g-service", "Attacks by Service", "service.keyword", "#22D3EE"),
    topn("g-rep", "Attacker Reputation", "reputation.keyword", "#FFA857"),
    topn("g-srcip", "Top Attacker Source IPs", "src_ip.keyword", "#FB5B6E"),
    topn("g-port", "Top Destination Ports", "dst_port", "#34D399"),
]

# dashboard layout (48-col grid): (id, so_type, x, y, w, h)
layout = [
    ("g-total", "visualization", 0, 0, 16, 6),
    ("g-ips", "visualization", 16, 0, 16, 6),
    ("g-countries", "visualization", 32, 0, 16, 6),
    ("g-map", "map", 0, 6, 48, 16),
    ("g-time", "visualization", 0, 22, 48, 11),
    ("g-country", "visualization", 0, 33, 16, 13),
    ("g-service", "visualization", 16, 33, 16, 13),
    ("g-rep", "visualization", 32, 33, 16, 13),
    ("g-srcip", "visualization", 0, 46, 24, 13),
    ("g-port", "visualization", 24, 46, 24, 13),
]
panels, refs = [], []
for n, (vid, sotype, x, y, w, h) in enumerate(layout, 1):
    pi = str(n)
    panels.append({"version": "8.15.0", "type": sotype,
                   "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pi},
                   "panelIndex": pi, "embeddableConfig": {}, "panelRefName": f"panel_{pi}"})
    refs.append({"name": f"panel_{pi}", "type": sotype, "id": vid})

objs.append({"id": "geoai-attack-dashboard", "type": "dashboard", "attributes": {
    "title": "GeoAI — Attack Analytics (Elastic)",
    "description": "T-Pot-style attack dashboard for the GeoAI FTTH platform",
    "panelsJSON": json.dumps(panels), "optionsJSON": '{"useMargins":true,"hidePanelTitles":false}',
    "version": 1, "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
    "refreshInterval": {"pause": False, "value": 10000},
    "kibanaSavedObjectMeta": {"searchSourceJSON": '{"query":{"query":"","language":"kuery"},"filter":[]}'}},
    "references": refs})

ndjson = "\n".join(json.dumps(o) for o in objs).encode()
boundary = "----geoai"
body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
        f"filename=\"geoai.ndjson\"\r\nContent-Type: application/ndjson\r\n\r\n").encode()
body += ndjson + f"\r\n--{boundary}--\r\n".encode()
status, resp = req(f"{KB}/api/saved_objects/_import?overwrite=true", data=body, raw=True,
                   headers={"kbn-xsrf": "true", "Content-Type": f"multipart/form-data; boundary={boundary}"})
r = json.loads(resp)
print(f"[*] import: success={r.get('success')} count={r.get('successCount')}")
if not r.get("success"):
    print(json.dumps(r.get("errors", []), indent=1)[:2000])
print("[*] dashboard: /app/dashboards#/view/geoai-attack-dashboard")
