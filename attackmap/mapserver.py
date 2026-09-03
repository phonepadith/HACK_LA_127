#!/usr/bin/env python3
"""Python-3 MapServer for the geoip-attack-map project.

The upstream AttackMapServer.py uses tornadoredis (dead on Python 3). This is a
drop-in replacement that serves the project's own frontend (index.html + static
+ flags) unchanged and bridges the Redis pub/sub channel to browser websockets.
"""
import json
import os
import threading

import redis
import tornado.ioloop
import tornado.web
import tornado.websocket

SITE = os.environ.get("SITE_DIR", "/app/repo/AttackMapServer")
REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
CHANNEL = "attack-map-production"
PORT = int(os.environ.get("MAP_PORT", "8888"))

clients = set()

# protocol -> arc/marker colour, from the project's AttackMapServer.py
SERVICE_RGB = {
    "FTP": "#ff0000", "SSH": "#ff8000", "TELNET": "#ffff00", "EMAIL": "#80ff00",
    "WHOIS": "#00ff00", "DNS": "#00ff80", "HTTP": "#00ffff", "HTTPS": "#0080ff",
    "SQL": "#0000ff", "SNMP": "#8000ff", "SMB": "#bf00ff", "AUTH": "#ff00ff",
    "RDP": "#ff0060", "DoS": "#ff0000", "ICMP": "#ffcccc", "OTHER": "#6600cc",
}


def transform(raw):
    """Reshape DataServer's Redis payload into the schema the frontend expects
    (same mapping the upstream tornadoredis MapServer performed)."""
    d = json.loads(raw)
    proto = d.get("protocol")
    return json.dumps({
        "type": d.get("msg_type"), "type2": d.get("msg_type2"), "type3": d.get("msg_type3"),
        "protocol": proto, "src_ip": d.get("src_ip"), "dst_ip": d.get("dst_ip"),
        "src_port": d.get("src_port"), "dst_port": d.get("dst_port"),
        "src_lat": d.get("latitude"), "src_long": d.get("longitude"),
        "dst_lat": d.get("dst_lat"), "dst_long": d.get("dst_long"),
        "city": d.get("city"), "continent": d.get("continent"),
        "continent_code": d.get("continent_code"), "country": d.get("country"),
        "iso_code": d.get("iso_code"), "postal_code": d.get("postal_code"),
        "color": SERVICE_RGB.get(proto, "#000000"),
        "event_count": d.get("event_count"), "continents_tracked": d.get("continents_tracked"),
        "countries_tracked": d.get("countries_tracked"), "ips_tracked": d.get("ips_tracked"),
        "unknowns": d.get("unknowns"), "event_time": d.get("event_time"),
        "country_to_code": d.get("country_to_code"), "ip_to_code": d.get("ip_to_code"),
    })


class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        self.render(os.path.join(SITE, "index.html"))


class WSHandler(tornado.websocket.WebSocketHandler):
    def check_origin(self, origin):
        return True  # behind our own tunnel

    def open(self):
        clients.add(self)

    def on_close(self):
        clients.discard(self)


def redis_loop(ioloop):
    """Subscribe to Redis and fan every published event out to all clients."""
    while True:
        try:
            sub = redis.StrictRedis(host=REDIS_HOST, port=6379, db=0).pubsub()
            sub.subscribe(CHANNEL)
            print("[*] Subscribed to Redis channel", CHANNEL, flush=True)
            for msg in sub.listen():
                if msg.get("type") != "message":
                    continue
                data = msg["data"]
                if isinstance(data, bytes):
                    data = data.decode("utf-8", "replace")
                try:
                    out = transform(data)
                except (ValueError, KeyError):
                    continue
                for c in list(clients):
                    ioloop.add_callback(c.write_message, out)
        except Exception as e:  # reconnect on any Redis hiccup
            print("[!] Redis loop error, retrying:", e, flush=True)
            tornado.ioloop.IOLoop.current().call_later(2, lambda: None)
            import time
            time.sleep(2)


def main():
    app = tornado.web.Application([
        (r"/", IndexHandler),
        (r"/websocket", WSHandler),
        (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": os.path.join(SITE, "static")}),
        (r"/flags/(.*)", tornado.web.StaticFileHandler, {"path": os.path.join(SITE, "static/flags")}),
    ], template_path=SITE)
    app.listen(PORT)
    ioloop = tornado.ioloop.IOLoop.current()
    threading.Thread(target=redis_loop, args=(ioloop,), daemon=True).start()
    print("[*] MapServer on :%d serving %s" % (PORT, SITE), flush=True)
    ioloop.start()


if __name__ == "__main__":
    main()
