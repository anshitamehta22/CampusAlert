#!/usr/bin/env python3
"""
CampusAlert v2 - local emergency broadcast system (Python stdlib only, no cloud).

PROTOTYPE: not a replacement for official emergency-alert systems.

One alert, four delivery paths, all on the local network:
  TCP        reliable push to registered desktop/CLI listeners (+ acknowledgements)
  UDP bcast  fire-and-forget to every device on the subnet (no registration needed)
  Multicast  efficient one-to-many to devices that joined group 239.255.42.99
  Web (SSE)  phones/laptops just open  http://<hub-ip>:8080/client  - no app install

Features
  * Admin dashboard  http://<hub-ip>:8080/     (PIN-protected sending, templates,
                                                live device list, ack tracking)
  * Zones            hostel / academic block / library / auditorium / ground / campus-wide
  * Acknowledgements devices confirm "received / I'm safe"; admin sees who responded
  * Security         HMAC-SHA256 signed alerts, replay window, PIN, brute-force lockout
  * Audit log        every alert appended to alerts.log (JSON lines)

Usage
  python campusalert.py server [--pin 4321] [--http-port 8080]
  python campusalert.py listen --server <hub-ip> --name "Lab PC" --zone academic
  python campusalert.py send --server <hub-ip> -l critical -z hostel -t "Fire" -m "Evacuate"
  python campusalert.py demo          # automated end-to-end self-test on localhost

Set CAMPUSALERT_SECRET (same on every machine) and CAMPUSALERT_PIN before real use.
"""
import argparse, hashlib, hmac, json, os, queue, socket, struct, sys, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TCP_PORT, UDP_PORT, HTTP_PORT = 5050, 5051, 8080
MCAST_GRP, MCAST_PORT = "239.255.42.99", 5052
MAX_AGE = 120                      # seconds an alert stays valid (replay protection)
LEVELS = ("info", "warning", "critical")
ZONE_LABELS = {"all": "Entire campus", "hostel": "Hostel", "academic": "Academic block",
               "library": "Library", "auditorium": "Auditorium", "ground": "Sports ground"}
ZONES = tuple(ZONE_LABELS)
ZONE_LIST = [z for z in ZONES if z != "all"]       # zones a device can sit in
SECRET = os.environ.get("CAMPUSALERT_SECRET", "change-me").encode()
DEFAULT_PIN = os.environ.get("CAMPUSALERT_PIN", "1234")


# ====================== alert format & signing ======================
def _sig(a):
    msg = "|".join(str(a[k]) for k in ("id", "ts", "level", "zone", "title", "body")).encode()
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()


def make_alert(level, title, body, zone="all"):
    a = {"id": uuid.uuid4().hex[:12], "ts": int(time.time()), "level": level,
         "zone": zone, "title": title, "body": body}
    a["sig"] = _sig(a)
    return a


def verify(a):
    try:
        return (a["level"] in LEVELS and a["zone"] in ZONES
                and abs(time.time() - int(a["ts"])) <= MAX_AGE
                and hmac.compare_digest(a["sig"], _sig(a)))
    except (KeyError, TypeError, ValueError):
        return False


def zone_match(alert_zone, device_zone):
    return alert_zone == "all" or alert_zone == device_zone


def encode(obj):
    return (json.dumps(obj) + "\n").encode()


# ============================== server ==============================
class Server:
    def __init__(self, host="0.0.0.0", tcp=TCP_PORT, udp=UDP_PORT, mgrp=MCAST_GRP,
                 mport=MCAST_PORT, bcast="255.255.255.255", http=HTTP_PORT,
                 pin=DEFAULT_PIN, logfile="alerts.log"):
        self.host, self.tcp, self.udp, self.http = host, tcp, udp, http
        self.mgrp, self.mport, self.bcast = mgrp, mport, bcast
        self.pin, self.logfile = pin, logfile
        self.lock, self.send_lock = threading.RLock(), threading.Lock()
        self.history, self.by_id = [], {}
        self.tcp_clients = {}      # conn -> {"name", "zone"}
        self.web_clients = {}      # queue -> {"name", "zone"}
        self.fails = {}            # ip -> [timestamps of failed PIN attempts]
        self.sock = self.httpd = None

    # ---- lifecycle ----
    def start(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.tcp))
        self.sock.listen(64)
        self.tcp = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()
        self.httpd = ThreadingHTTPServer((self.host, self.http), make_handler(self))
        self.httpd.daemon_threads = True
        self.http = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        for s in (self.sock,):
            if s:
                s.close()
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()

    # ---- TCP listeners / senders ----
    def _accept(self):
        while True:
            try:
                c, addr = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c, addr), daemon=True).start()

    def _handle(self, c, addr):
        try:
            for line in c.makefile("rb"):
                try:
                    m = json.loads(line)
                except ValueError:
                    continue
                t = m.get("type")
                if t == "hello":
                    zone = m.get("zone") if m.get("zone") in ZONE_LIST else ZONE_LIST[0]
                    name = str(m.get("name") or addr[0])[:40]
                    with self.lock:
                        self.tcp_clients[c] = {"name": name, "zone": zone}
                    print(f"[server] listener joined: {name} ({zone}) from {addr[0]}")
                elif t == "ack":
                    self.ack(m.get("id"), m.get("name") or addr[0])
                elif t == "alert":
                    a = m.get("alert", {})
                    if not verify(a):
                        c.sendall(encode({"type": "error", "error": "bad signature or stale"}))
                        continue
                    res = self.broadcast(a)
                    c.sendall(encode({"type": "sent", "id": a["id"], "reached": res}))
        except OSError:
            pass
        finally:
            with self.lock:
                gone = self.tcp_clients.pop(c, None)
            c.close()
            if gone:
                print(f"[server] listener left: {gone['name']}")

    # ---- core: deliver an alert on every path ----
    def broadcast(self, a):
        with self.send_lock:
            with self.lock:
                if a["id"] in self.by_id:
                    return None
                rec = {"alert": a, "acks": {}, "reached": 0}
                self.by_id[a["id"]] = rec
                self.history.insert(0, rec)
                for old in self.history[100:]:
                    self.by_id.pop(old["alert"]["id"], None)
                del self.history[100:]
                tcp_t = [c for c, i in self.tcp_clients.items() if zone_match(a["zone"], i["zone"])]
                web_t = [q for q, i in self.web_clients.items() if zone_match(a["zone"], i["zone"])]
            print(f"[server] ALERT {a['level'].upper()} -> {ZONE_LABELS[a['zone']]}: {a['title']}")
            if self.logfile:
                try:
                    with open(self.logfile, "a", encoding="utf-8") as f:
                        f.write(json.dumps(a) + "\n")
                except OSError:
                    pass
            data = encode({"type": "alert", "alert": a})
            n_tcp = 0
            for c in tcp_t:
                try:
                    c.sendall(data)
                    n_tcp += 1
                except OSError:
                    with self.lock:
                        self.tcp_clients.pop(c, None)
            for q in web_t:
                q.put({"alert": a, "replay": False})
            rec["reached"] = n_tcp + len(web_t)
            self._udp_out(data)
            return {"tcp": n_tcp, "web": len(web_t)}

    def _udp_out(self, data):
        """UDP broadcast + multicast. Repeated 3x because UDP can drop packets."""
        for target, opts in (((self.bcast, self.udp), self._bcast_opts),
                             ((self.mgrp, self.mport), self._mcast_opts)):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                opts(s)
                for _ in range(3):
                    try:
                        s.sendto(data, target)
                    except OSError as e:
                        print(f"[server] send to {target} failed: {e}")
                        break
                    time.sleep(0.05)
            finally:
                s.close()

    @staticmethod
    def _bcast_opts(s):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    @staticmethod
    def _mcast_opts(s):
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)   # never leave the LAN
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

    # ---- acks, state, web clients ----
    def ack(self, aid, name):
        with self.lock:
            rec = self.by_id.get(aid)
            if rec and isinstance(name, str):
                rec["acks"][name[:40]] = int(time.time())
                return True
        return False

    def state(self):
        with self.lock:
            return {
                "zones": ZONE_LABELS,
                "tcp": [dict(i) for i in self.tcp_clients.values()],
                "web": [dict(i) for i in self.web_clients.values()],
                "history": [{"alert": r["alert"], "reached": r["reached"],
                             "acks": sorted(r["acks"])} for r in self.history[:30]],
            }

    def add_web(self, q, name, zone):
        with self.lock:
            self.web_clients[q] = {"name": name, "zone": zone}

    def remove_web(self, q):
        with self.lock:
            self.web_clients.pop(q, None)

    def recent(self, zone, window=600):
        now, out = time.time(), []
        with self.lock:
            for r in reversed(self.history):
                a = r["alert"]
                if now - a["ts"] <= window and zone_match(a["zone"], zone):
                    out.append({"alert": a, "replay": True})
        return out

    def pin_ok(self, ip, pin):
        now = time.time()
        with self.lock:
            recent = [t for t in self.fails.get(ip, []) if now - t < 60]
            self.fails[ip] = recent
            if len(recent) >= 5:
                return None                       # locked out
            if hmac.compare_digest(str(pin).encode(), self.pin.encode()):
                return True
            recent.append(now)
            return False


# ========================== HTTP / web layer ==========================
def make_handler(app):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            pass

        def _send(self, code, body, ctype="application/json"):
            if isinstance(body, (dict, list)):
                body = json.dumps(body)
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self):
            try:
                n = int(self.headers.get("Content-Length", 0))
                if n > 10000:
                    return None
                d = json.loads(self.rfile.read(n) or b"{}")
                return d if isinstance(d, dict) else None
            except (ValueError, OSError):
                return None

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/":
                self._send(200, ADMIN_HTML, "text/html")
            elif u.path == "/client":
                self._send(200, CLIENT_HTML, "text/html")
            elif u.path == "/api/state":
                self._send(200, app.state())
            elif u.path == "/events":
                self._sse(parse_qs(u.query))
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            d = self._json()
            if d is None:
                return self._send(400, {"error": "bad request"})
            if path == "/api/send":
                ok = app.pin_ok(self.client_address[0], d.get("pin", ""))
                if ok is None:
                    return self._send(429, {"error": "Too many wrong PINs. Wait a minute."})
                if not ok:
                    return self._send(403, {"error": "Wrong PIN"})
                level, zone = d.get("level"), d.get("zone", "all")
                title, body = str(d.get("title", "")).strip(), str(d.get("body", "")).strip()
                if level not in LEVELS or zone not in ZONES or not title or len(title) > 80 or len(body) > 300:
                    return self._send(400, {"error": "Invalid alert fields"})
                a = make_alert(level, title, body, zone)
                self._send(200, {"ok": True, "id": a["id"], "reached": app.broadcast(a)})
            elif path == "/api/ack":
                ok = app.ack(d.get("id"), d.get("name", "web device"))
                self._send(200 if ok else 404, {"ok": ok})
            else:
                self._send(404, {"error": "not found"})

        def _sse(self, qs):
            name = (qs.get("name", ["web device"])[0] or "web device")[:40]
            zone = qs.get("zone", [ZONE_LIST[0]])[0]
            if zone not in ZONE_LIST:
                zone = ZONE_LIST[0]
            q = queue.Queue()
            app.add_web(q, name, zone)
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                for item in app.recent(zone):          # alerts the device missed while offline
                    self.wfile.write(("data: " + json.dumps(item) + "\n\n").encode())
                self.wfile.flush()
                while True:
                    try:
                        item = q.get(timeout=15)
                        self.wfile.write(("data: " + json.dumps(item) + "\n\n").encode())
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")         # keep-alive
                    self.wfile.flush()
            except (OSError, ValueError):
                pass
            finally:
                app.remove_web(q)
    return H


# ============================ listener ============================
class Listener:
    """A device that receives alerts over TCP + UDP broadcast + multicast."""

    def __init__(self, server_host, tcp=TCP_PORT, udp=UDP_PORT, mgrp=MCAST_GRP,
                 mport=MCAST_PORT, name=None, zone=None, on_alert=None):
        self.server_host, self.tcp, self.udp = server_host, tcp, udp
        self.mgrp, self.mport = mgrp, mport
        self.name = name or socket.gethostname()
        self.zone = zone if zone in ZONE_LIST else ZONE_LIST[0]
        self.on_alert = on_alert or self.show
        self.seen, self.lock, self.send_lock = set(), threading.Lock(), threading.Lock()
        self.sock, self.stop_flag = None, threading.Event()

    def show(self, a, via):
        icon = {"info": "i", "warning": "!", "critical": "!!!"}[a["level"]]
        print(f"\n{'=' * 54}\n[{icon}] {a['level'].upper()} | {ZONE_LABELS[a['zone']]} | via {via}\n"
              f"    {a['title']}\n    {a['body']}\n{'=' * 54}", flush=True)
        if a["level"] == "critical":
            print("\a", end="", flush=True)

    def _deliver(self, raw, via):
        try:
            a = json.loads(raw)["alert"]
        except (ValueError, KeyError, TypeError):
            return
        if not verify(a) or not zone_match(a["zone"], self.zone):
            return
        with self.lock:                      # same alert arrives on several paths: show once
            if a["id"] in self.seen:
                return
            self.seen.add(a["id"])
        self.on_alert(a, via)
        self._ack(a)

    def _ack(self, a):
        s = self.sock
        if s:
            try:
                with self.send_lock:
                    s.sendall(encode({"type": "ack", "id": a["id"], "name": self.name}))
            except OSError:
                pass

    def _tcp_loop(self):
        while not self.stop_flag.is_set():
            try:
                with socket.create_connection((self.server_host, self.tcp), timeout=5) as s:
                    s.settimeout(None)
                    self.sock = s
                    s.sendall(encode({"type": "hello", "name": self.name, "zone": self.zone}))
                    for line in s.makefile("rb"):
                        self._deliver(line, "TCP")
            except OSError:
                pass
            finally:
                self.sock = None
            self.stop_flag.wait(2)           # reconnect backoff

    def _udp_loop(self, mcast):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            s.bind(("", self.mport if mcast else self.udp))
            if mcast:
                mreq = struct.pack("4sl", socket.inet_aton(self.mgrp), socket.INADDR_ANY)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError as e:
            print(f"[listen] {'multicast' if mcast else 'broadcast'} unavailable: {e}")
            return
        s.settimeout(1)
        while not self.stop_flag.is_set():
            try:
                data, _ = s.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            self._deliver(data, "multicast" if mcast else "UDP broadcast")

    def start(self):
        for t in (self._tcp_loop, lambda: self._udp_loop(False), lambda: self._udp_loop(True)):
            threading.Thread(target=t, daemon=True).start()

    def stop(self):
        self.stop_flag.set()


# ============================== sender ==============================
def send_alert(host, level, title, body, zone="all", tcp=TCP_PORT):
    a = make_alert(level, title, body, zone)
    with socket.create_connection((host, tcp), timeout=5) as s:
        s.sendall(encode({"type": "alert", "alert": a}))
        return json.loads(s.makefile("rb").readline())


# ============================ web pages ============================
ADMIN_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CampusAlert Control</title>
<style>
:root{--bg:#0f1420;--card:#171d2d;--ink:#e8ecf5;--mut:#8b95ad;--line:#262e45;--info:#3b82f6;--warning:#f59e0b;--critical:#ef4444;--ok:#22c55e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center;flex-wrap:wrap}
header h1{margin:0;font-size:20px}header span{color:var(--mut);font-size:13px}.grow{flex:1}
main{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px 24px;max-width:1200px;margin:auto}
@media(max-width:860px){main{grid-template-columns:1fr;padding:12px}}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}.wide{grid-column:1/-1}
h2{margin:0 0 12px;font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut)}
label{display:block;font-size:12px;color:var(--mut);margin:10px 0 4px}
input,select,textarea{width:100%;background:#0f1420;color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:9px 10px;font:inherit}
textarea{min-height:70px;resize:vertical}
.row{display:flex;gap:8px;flex-wrap:wrap}.row>*{flex:1}
button{font:inherit;border:1px solid var(--line);background:#0f1420;color:var(--ink);padding:8px 12px;border-radius:8px;cursor:pointer}
button:hover{border-color:var(--mut)}
.lv.on[data-l=info]{background:var(--info);border-color:var(--info)}.lv.on[data-l=warning]{background:var(--warning);border-color:var(--warning);color:#111}
.lv.on[data-l=critical]{background:var(--critical);border-color:var(--critical)}
.send{width:100%;margin-top:14px;padding:12px;font-weight:600;background:var(--critical);border-color:var(--critical)}
.tpl button{font-size:12px;padding:6px 9px}.tpl{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px}
#msg{margin-top:10px;font-size:13px;min-height:18px}.ok{color:var(--ok)}.bad{color:var(--critical)}
.chip{display:inline-block;background:#0f1420;border:1px solid var(--line);border-radius:99px;padding:3px 10px;margin:3px 4px 0 0;font-size:12px}
.hint{font-size:13px;color:var(--mut);margin-top:10px}code{background:#0f1420;padding:2px 6px;border-radius:5px}
.item{border-top:1px solid var(--line);padding:12px 0}.item:first-of-type{border-top:0}
.badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px;margin-right:8px;text-transform:uppercase;color:#fff}
.badge.info{background:var(--info)}.badge.warning{background:var(--warning);color:#111}.badge.critical{background:var(--critical)}
.bar{height:6px;background:#0f1420;border-radius:9px;overflow:hidden;margin:8px 0 4px}.bar i{display:block;height:100%;background:var(--ok)}
.mut{color:var(--mut);font-size:12px}
</style></head><body>
<header><h1>CampusAlert</h1><span>Local emergency broadcast &middot; no cloud &middot; prototype</span><span class="grow"></span>
<span id="count"></span></header>
<main>
<section class="card"><h2>Send alert</h2>
<div class="tpl" id="tpl"></div>
<label>Severity</label>
<div class="row" id="levels"><button class="lv on" data-l="info">Info</button><button class="lv" data-l="warning">Warning</button><button class="lv" data-l="critical">Critical</button></div>
<label>Send to</label><select id="zone"></select>
<label>Title</label><input id="title" maxlength="80" placeholder="Short headline">
<label>Message</label><textarea id="body" maxlength="300" placeholder="What should people do?"></textarea>
<label>Operator PIN</label><input id="pin" type="password" placeholder="PIN" autocomplete="off">
<button class="send" id="go">Broadcast alert</button><div id="msg"></div></section>
<section class="card"><h2>Connected devices</h2><div id="devs"></div>
<p class="hint">Students/staff open <code id="url"></code> on their phone, pick their zone and tap Connect.</p></section>
<section class="card wide"><h2>Alert history &amp; acknowledgements</h2><div id="hist"></div></section>
</main>
<script>
const $=s=>document.querySelector(s);
function el(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}
const T={fire:{level:'critical',zone:'all',title:'Fire alarm - evacuate now',body:'Leave the building by the nearest exit. Do not use lifts. Assemble at the sports ground.'},
drill:{level:'warning',zone:'all',title:'Fire drill in 10 minutes',body:'This is a drill. Assemble at the sports ground when you hear the bell.'},
weather:{level:'warning',zone:'all',title:'Severe weather warning',body:'Heavy rain and lightning expected. Stay indoors, away from windows.'},
event:{level:'info',zone:'auditorium',title:'Event update',body:'The seminar has moved to Seminar Hall 2 and starts at 3:30 PM.'},
clear:{level:'info',zone:'all',title:'All clear',body:'The situation is resolved. Normal activities may resume.'}};
const NAMES={fire:'Fire',drill:'Fire drill',weather:'Weather',event:'Event update',clear:'All clear'};
let level='info',zonesReady=false;
function setLevel(l){level=l;document.querySelectorAll('.lv').forEach(b=>b.classList.toggle('on',b.dataset.l===l))}
document.querySelectorAll('.lv').forEach(b=>b.onclick=()=>setLevel(b.dataset.l));
for(const k in T){const b=el('button','',NAMES[k]);b.onclick=()=>{const t=T[k];setLevel(t.level);$('#zone').value=t.zone;$('#title').value=t.title;$('#body').value=t.body};$('#tpl').append(b)}
$('#url').textContent=location.host+'/client';
$('#go').onclick=async()=>{
  const zone=$('#zone').value,title=$('#title').value.trim();
  if(!title){return say('Enter a title.',0)}
  if(level==='critical'&&!confirm('Send a CRITICAL alert to: '+$('#zone').selectedOptions[0].text+'?'))return;
  const r=await fetch('/api/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({level,zone,title,body:$('#body').value,pin:$('#pin').value})});
  const d=await r.json();
  if(r.ok){say('Sent. Reached '+(d.reached.tcp+d.reached.web)+' registered device(s) + UDP/multicast broadcast.',1);refresh()}else say(d.error||'Failed',0)};
function say(t,ok){const m=$('#msg');m.textContent=t;m.className=ok?'ok':'bad'}
function render(s){
  if(!zonesReady){for(const z in s.zones){const o=el('option','',s.zones[z]);o.value=z;$('#zone').append(o)}zonesReady=true}
  const all=s.tcp.map(d=>({...d,k:'TCP'})).concat(s.web.map(d=>({...d,k:'Web'})));
  $('#count').textContent=all.length+' device(s) online';
  const dv=$('#devs');dv.replaceChildren();
  if(!all.length)dv.append(el('div','mut','No devices connected yet.'));
  all.forEach(d=>dv.append(el('span','chip',d.name+' - '+s.zones[d.zone]+' ('+d.k+')')));
  const h=$('#hist');h.replaceChildren();
  if(!s.history.length)h.append(el('div','mut','No alerts sent yet.'));
  s.history.forEach(r=>{const a=r.alert,it=el('div','item'),top=el('div');
    top.append(el('span','badge '+a.level,a.level),el('b','',a.title));it.append(top);
    it.append(el('div','mut',s.zones[a.zone]+' - '+new Date(a.ts*1000).toLocaleTimeString()+' - '+a.body));
    const pct=r.reached?Math.min(100,Math.round(100*r.acks.length/r.reached)):0,bar=el('div','bar'),i=el('i');i.style.width=pct+'%';bar.append(i);it.append(bar);
    it.append(el('div','mut','Delivered to '+r.reached+' registered device(s) - '+r.acks.length+' acknowledged'+(r.acks.length?': '+r.acks.join(', '):'')));
    h.append(it)})}
async function refresh(){try{render(await (await fetch('/api/state')).json())}catch(e){}}
refresh();setInterval(refresh,2000);
</script></body></html>"""

CLIENT_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CampusAlert</title>
<style>
:root{--bg:#0f1420;--card:#171d2d;--ink:#e8ecf5;--mut:#8b95ad;--line:#262e45;--info:#3b82f6;--warning:#f59e0b;--critical:#ef4444;--ok:#22c55e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:520px;margin:auto;padding:20px}h1{font-size:22px;margin:0 0 4px}.mut{color:var(--mut);font-size:13px}
label{display:block;font-size:12px;color:var(--mut);margin:14px 0 4px}
input,select{width:100%;background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:10px;padding:12px;font:inherit}
button{font:inherit;width:100%;margin-top:18px;padding:14px;border:0;border-radius:10px;background:var(--info);color:#fff;font-weight:600}
#status{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--mut);margin-right:6px}#status.on{background:var(--ok)}
.past{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--info);border-radius:10px;padding:10px 12px;margin-top:10px}
.past.warning{border-left-color:var(--warning)}.past.critical{border-left-color:var(--critical)}
#ov{position:fixed;inset:0;display:none;flex-direction:column;justify-content:center;padding:28px;text-align:center;color:#fff;z-index:9}
#ov.info{background:#1d4ed8}#ov.warning{background:#b45309}#ov.critical{background:#b91c1c;animation:pulse 1s infinite}
@keyframes pulse{50%{filter:brightness(1.35)}}
#ov h2{font-size:30px;margin:10px 0}#ov p{font-size:19px;margin:6px 0 24px}#ov .tag{font-size:13px;letter-spacing:.12em;text-transform:uppercase;opacity:.9}
#ov button{background:#fff;color:#111;font-size:18px}
</style></head><body><div class="wrap">
<h1>CampusAlert</h1><div class="mut">Receive campus announcements on this device.</div>
<div id="setup"><label>Your name</label><input id="name" maxlength="40" placeholder="e.g. Krishika">
<label>Where are you?</label><select id="zone"></select>
<button id="join">Connect</button></div>
<div id="live" style="display:none"><p><span id="status"></span><span id="st">Connecting...</span></p>
<div class="mut">Keep this page open. You will be alerted instantly.</div><h3>Recent alerts</h3><div id="list"></div></div>
</div>
<div id="ov"><div class="tag" id="otag"></div><h2 id="ott"></h2><p id="obd"></p><div class="mut" id="otm" style="color:#fff;opacity:.8"></div>
<button id="ack">I got it / I'm safe</button></div>
<script>
const $=s=>document.querySelector(s);
function el(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}
const Z={hostel:'Hostel',academic:'Academic block',library:'Library',auditorium:'Auditorium',ground:'Sports ground'};
for(const z in Z){const o=el('option','',Z[z]);o.value=z;$('#zone').append(o)}
try{$('#name').value=localStorage.getItem('ca_name')||'';$('#zone').value=localStorage.getItem('ca_zone')||'hostel'}catch(e){}
let ctx,cur,name,beepT;
function beep(){if(!ctx)return;try{const o=ctx.createOscillator(),g=ctx.createGain();o.frequency.value=880;g.gain.value=.25;o.connect(g);g.connect(ctx.destination);o.start();o.stop(ctx.currentTime+.3)}catch(e){}}
function show(a){cur=a;const ov=$('#ov');ov.className=a.level;ov.style.display='flex';
  $('#otag').textContent=a.level+' alert';$('#ott').textContent=a.title;$('#obd').textContent=a.body;$('#otm').textContent=new Date(a.ts*1000).toLocaleTimeString();
  if(navigator.vibrate)navigator.vibrate(a.level==='critical'?[500,200,500,200,500]:[250]);
  clearInterval(beepT);if(a.level!=='info'){beep();beepT=setInterval(beep,a.level==='critical'?900:2500)}}
$('#ack').onclick=()=>{clearInterval(beepT);$('#ov').style.display='none';
  fetch('/api/ack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:cur.id,name:name})})};
$('#join').onclick=()=>{
  name=$('#name').value.trim()||'Phone-'+Math.floor(Math.random()*900+100);const zone=$('#zone').value;
  try{localStorage.setItem('ca_name',name);localStorage.setItem('ca_zone',zone)}catch(e){}
  try{ctx=new (window.AudioContext||window.webkitAudioContext)()}catch(e){}
  $('#setup').style.display='none';$('#live').style.display='block';
  const es=new EventSource('/events?name='+encodeURIComponent(name)+'&zone='+zone);const seen=new Set();
  es.onopen=()=>{$('#status').className='on';$('#st').textContent='Connected as '+name+' ('+Z[zone]+')'};
  es.onerror=()=>{$('#status').className='';$('#st').textContent='Reconnecting...'};
  es.onmessage=e=>{const m=JSON.parse(e.data),a=m.alert;if(seen.has(a.id))return;seen.add(a.id);
    const p=el('div','past '+a.level);p.append(el('b','',a.title),el('div','mut',new Date(a.ts*1000).toLocaleTimeString()+' - '+a.body));
    $('#list').prepend(p);if(!m.replay)show(a)}};
</script></body></html>"""


# =============================== CLI ===============================
def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))          # no packet is actually sent
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def demo():
    """Automated end-to-end self-test on localhost (non-default ports)."""
    import urllib.request, urllib.error
    results = []

    def check(label, cond):
        results.append(bool(cond))
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}")

    def http(port, path, data=None):
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=json.dumps(data).encode() if data is not None else None,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def sse_client(port, name, zone, out):
        try:
            r = urllib.request.urlopen(f"http://127.0.0.1:{port}/events?name={name}&zone={zone}", timeout=10)
            for line in r:
                if line.startswith(b"data: "):
                    out.append(json.loads(line[6:]))
        except OSError:
            pass

    srv = Server(host="127.0.0.1", tcp=0, udp=55051, mport=55052, bcast="127.0.0.1",
                 http=0, pin="4321", logfile=None)
    srv.start()
    P = srv.http
    print(f"Server up: TCP :{srv.tcp}  HTTP :{P}")

    tcp_got, udp_got = [], []
    # listener A: TCP only (its UDP ports are parked elsewhere); zone = hostel
    A = Listener("127.0.0.1", tcp=srv.tcp, udp=55061, mport=55062, name="hostel-pc", zone="hostel",
                 on_alert=lambda a, via: tcp_got.append(via))
    # listener B: cannot reach TCP (port 1) -> must be reached by UDP broadcast / multicast
    B = Listener("127.0.0.1", tcp=1, udp=55051, mport=55052, name="udp-only", zone="hostel",
                 on_alert=lambda a, via: udp_got.append(via))
    A.start(); B.start()
    phone, lib = [], []
    threading.Thread(target=sse_client, args=(P, "phone", "hostel", phone), daemon=True).start()
    threading.Thread(target=sse_client, args=(P, "libphone", "library", lib), daemon=True).start()
    time.sleep(1.2)

    print("Tests:")
    code, _ = http(P, "/api/send", {"pin": "0000", "level": "critical", "zone": "hostel", "title": "x", "body": "y"})
    check("wrong PIN rejected (403)", code == 403)
    code, d = http(P, "/api/send", {"pin": "4321", "level": "critical", "zone": "hostel",
                                    "title": "Fire alarm", "body": "Evacuate via stairs"})
    check("correct PIN accepted (200)", code == 200 and d.get("ok"))
    aid = d.get("id")
    time.sleep(1.2)
    check("TCP listener received alert (via TCP)", tcp_got == ["TCP"])
    check("UDP-only listener received alert (broadcast or multicast)",
          len(udp_got) == 1 and udp_got[0] in ("UDP broadcast", "multicast"))
    print(f"        UDP-only device got it via: {udp_got}")
    check("web phone in same zone received alert",
          any(m["alert"]["id"] == aid and not m["replay"] for m in phone))
    check("web phone in OTHER zone did NOT receive it (zone filtering)",
          not any(m["alert"]["id"] == aid for m in lib))
    code, _ = http(P, "/api/ack", {"id": aid, "name": "phone"})
    time.sleep(0.4)
    st = http(P, "/api/state")[1]
    acks = st["history"][0]["acks"]
    check("acknowledgements recorded (TCP auto-ack + web ack)", "phone" in acks and "hostel-pc" in acks)
    check("dashboard state lists devices", len(st["tcp"]) == 1 and len(st["web"]) == 2)
    bad = make_alert("info", "x", "y")
    bad["body"] = "tampered"
    check("tampered alert fails signature check", not verify(bad))
    old = make_alert("info", "x", "y")
    old["ts"] -= 1000
    old["sig"] = _sig(old)
    check("stale (replayed) alert rejected", not verify(old))
    for _ in range(6):
        code, _ = http(P, "/api/send", {"pin": "nope", "level": "info", "zone": "all", "title": "t", "body": ""})
    check("PIN brute-force lockout (429)", code == 429)
    A.stop(); B.stop(); srv.stop()
    ok = all(results)
    print(f"\n{sum(results)}/{len(results)} checks passed")
    return ok


def main():
    p = argparse.ArgumentParser(description="CampusAlert v2 - local emergency broadcast")
    sub = p.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("server")
    sv.add_argument("--pin", default=DEFAULT_PIN)
    sv.add_argument("--http-port", type=int, default=HTTP_PORT)
    ls = sub.add_parser("listen")
    ls.add_argument("--server", default="127.0.0.1")
    ls.add_argument("--name", default=None)
    ls.add_argument("--zone", default=ZONE_LIST[0], choices=ZONE_LIST)
    sd = sub.add_parser("send")
    sd.add_argument("--server", default="127.0.0.1")
    sd.add_argument("-l", "--level", choices=LEVELS, default="info")
    sd.add_argument("-z", "--zone", choices=ZONES, default="all")
    sd.add_argument("-t", "--title", required=True)
    sd.add_argument("-m", "--message", default="")
    sub.add_parser("demo")
    args = p.parse_args()

    if args.cmd == "server":
        srv = Server(pin=args.pin, http=args.http_port)
        srv.start()
        ip = lan_ip()
        print(f"CampusAlert hub running\n  Admin dashboard : http://{ip}:{srv.http}/\n"
              f"  Phone client    : http://{ip}:{srv.http}/client\n"
              f"  TCP {srv.tcp} | UDP bcast {srv.udp} | multicast {srv.mgrp}:{srv.mport}")
        if args.pin == "1234":
            print("  WARNING: default PIN in use - set --pin or CAMPUSALERT_PIN")
        threading.Event().wait()
    elif args.cmd == "listen":
        Listener(args.server, name=args.name, zone=args.zone).start()
        print(f"[listen] waiting for alerts in zone '{args.zone}' (Ctrl+C to quit)")
        threading.Event().wait()
    elif args.cmd == "send":
        print(send_alert(args.server, args.level, args.title, args.message, args.zone))
    elif args.cmd == "demo":
        sys.exit(0 if demo() else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
