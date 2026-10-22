"""
Smart WiFi Monitor — device self-registration (additive module).

A device joins the hotspot, opens  http://<laptop-ip>:5000/portal , logs in with its
user account and presses "Register this device". The backend then:

  * takes the device IP from the TCP connection (request.remote_addr — NOT from
    headers, which a client could spoof),
  * looks up the device MAC in the OS ARP table (works on the same Wi-Fi/LAN subnet),
  * creates (or updates) the device row for that user,
  * marks it 'trusted' (auto-approve) or 'pending' (admin must approve).

The proxy (proxy_server.py) then lets the device through as soon as it is trusted.

Endpoints
---------
    GET  /portal                       simple web page (login + register button)
    GET  /api/devices/whoami           my IP / MAC / registration status   (login)
    POST /api/devices/register-self    register the calling device         (login)
    GET  /proxy.pac                    auto proxy config for phones/laptops

Env vars (all optional)
-----------------------
    SELF_REGISTER_ENABLED=1
    SELF_REGISTER_AUTO_APPROVE=1     1 = trusted immediately, 0 = 'pending' for admin
    SELF_REGISTER_MAX_DEVICES=3      per non-admin user
    SELF_REGISTER_PRIORITY=low       priority tier for newly registered devices
    PROXY_PORT=8888                  used in proxy.pac / portal instructions
"""

from __future__ import annotations

import ipaddress
import os
import re
import sqlite3
import subprocess

_MAC_FIND_RE = re.compile(r"(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}")
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def lookup_mac(ip: str) -> str | None:
    """Find the MAC for a LAN IP from the OS neighbour (ARP) table. None if unknown."""
    try:
        ipaddress.ip_address(ip)  # never pass unvalidated text to a subprocess
    except ValueError:
        return None

    commands = (
        [["arp", "-a", ip]]
        if os.name == "nt"
        else [["ip", "neigh", "show", ip], ["arp", "-n", ip]]
    )
    for cmd in commands:
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3, check=False
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for match in _MAC_FIND_RE.finditer(out):
            raw = match.group(0)
            parts = [p.zfill(2) for p in re.split(r"[:-]", raw)]
            mac = ":".join(parts).upper()
            if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                return mac
    return None


_neighbor_cache: dict = {"ts": 0.0, "data": []}


def _norm_mac(raw: str) -> str:
    return ":".join(p.zfill(2) for p in re.split(r"[:-]", raw)).upper()


def list_neighbors(subnet: str | None = None, max_age_sec: float = 3.0) -> list[dict]:
    """
    Devices recently seen on the local network, from the OS ARP/neighbour table.
    Returns [{"ip": ..., "mac": ...}]. The table can keep a device for a few minutes
    after it left, so treat it as "seen recently", not a live guarantee.
    """
    import time

    if time.time() - _neighbor_cache["ts"] < max_age_sec:
        entries = _neighbor_cache["data"]
    else:
        commands = (
            [["arp", "-a"]] if os.name == "nt"
            else [["ip", "neigh", "show"], ["arp", "-an"]]
        )
        entries = []
        for cmd in commands:
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=4, check=False).stdout
            except (OSError, subprocess.SubprocessError):
                continue
            for line in out.splitlines():
                low = line.lower()
                if "failed" in low or "incomplete" in low or "invalid" in low:
                    continue
                ip_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
                mac_m = _MAC_FIND_RE.search(line)
                if not ip_m or not mac_m:
                    continue
                if os.name == "nt" and "dynamic" not in low:
                    continue  # skips static/broadcast/multicast rows on Windows
                mac = _norm_mac(mac_m.group(0))
                if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    continue
                entries.append({"ip": ip_m.group(1), "mac": mac})
            if entries:
                break
        _neighbor_cache["ts"] = time.time()
        _neighbor_cache["data"] = entries

    net = None
    if subnet:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            net = None
    result, seen = [], set()
    for e in entries:
        try:
            addr = ipaddress.ip_address(e["ip"])
        except ValueError:
            continue
        if addr.is_multicast or e["ip"].endswith(".255"):
            continue
        if net is not None:
            if addr not in net:
                continue
        elif not addr.is_private:
            continue
        if e["ip"] in seen:
            continue
        seen.add(e["ip"])
        result.append(e)
    return result


PORTAL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Smart WiFi — Register device</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:16px}
  .card{max-width:440px;margin:24px auto;background:#1e293b;border-radius:14px;padding:20px}
  h1{font-size:1.25rem;margin:0 0 4px} p{color:#94a3b8;font-size:.9rem}
  label{display:block;margin:12px 0 4px;font-size:.85rem;color:#94a3b8}
  input{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #334155;
        background:#0f172a;color:#e2e8f0;font-size:1rem}
  button{width:100%;margin-top:16px;padding:12px;border:0;border-radius:8px;background:#3b82f6;
         color:#fff;font-size:1rem;cursor:pointer}
  button:disabled{opacity:.5} .msg{margin-top:12px;font-size:.9rem;white-space:pre-wrap}
  .ok{color:#4ade80} .err{color:#f87171} .kv{font-family:ui-monospace,monospace;font-size:.85rem}
  code{background:#0f172a;padding:2px 6px;border-radius:4px}
  .hide{display:none}
</style></head><body><div class="card">
<h1>Smart WiFi Monitor</h1>
<p>Sign in, then register this device to use the internet.</p>

<div id="loginBox">
  <label for="u">Username</label><input id="u" autocomplete="username">
  <label for="p">Password</label><input id="p" type="password" autocomplete="current-password">
  <button id="loginBtn">Sign in</button>
</div>

<div id="devBox" class="hide">
  <p>Signed in as <b id="who"></b></p>
  <div class="kv">IP: <span id="ip">-</span><br>MAC: <span id="mac">-</span><br>Status: <b id="st">-</b></div>
  <label for="name">Device name</label><input id="name" maxlength="40" placeholder="e.g. My-iPhone">
  <button id="regBtn">Register this device</button>
  <div id="how" class="msg hide"></div>
</div>
<div id="msg" class="msg"></div>
</div>
<script>
let token = null;
const $ = id => document.getElementById(id);
function say(t, cls){ const m=$('msg'); m.textContent=t||''; m.className='msg '+(cls||''); }
async function api(path, opts){
  opts = opts || {}; opts.headers = Object.assign({'Content-Type':'application/json'}, opts.headers||{});
  if(token) opts.headers['Authorization'] = 'Bearer ' + token;
  const r = await fetch(path, opts); let j = {}; try{ j = await r.json(); }catch(e){}
  return {ok:r.ok, status:r.status, data:j};
}
function showHow(info){
  const h = $('how'); const host = location.hostname; const port = info.proxy_port;
  h.textContent = 'Set your Wi-Fi proxy to finish:\\n' +
    'Automatic: ' + location.origin + '/proxy.pac\\n' +
    'or Manual: server ' + host + '  port ' + port;
  h.className = 'msg';
}
async function loadWho(){
  const r = await api('/api/devices/whoami');
  if(!r.ok){ say(r.data.message || 'Could not load device info', 'err'); return; }
  const d = r.data;
  $('ip').textContent = d.ip || '-'; $('mac').textContent = d.mac || 'not detected';
  $('st').textContent = d.device ? d.device.status : 'not registered';
  if(d.device && !$('name').value) $('name').value = d.device.device_name;
  if(d.device && d.device.status === 'trusted') showHow(d);
}
$('loginBtn').onclick = async () => {
  say('Signing in...');
  const r = await api('/api/login', {method:'POST', body: JSON.stringify({username:$('u').value, password:$('p').value})});
  if(!r.ok){ say(r.data.message || 'Login failed', 'err'); return; }
  token = r.data.token; $('who').textContent = r.data.user.username;
  $('loginBox').className='hide'; $('devBox').className=''; $('p').value=''; say('');
  loadWho();
};
$('regBtn').onclick = async () => {
  $('regBtn').disabled = true; say('Registering...');
  const r = await api('/api/devices/register-self', {method:'POST', body: JSON.stringify({device_name:$('name').value})});
  $('regBtn').disabled = false;
  if(!r.ok){ say(r.data.message || 'Registration failed', 'err'); return; }
  say(r.data.message, 'ok'); await loadWho();
};
</script></body></html>
"""


def register_self_service_routes(
    app,
    *,
    get_db,
    login_required,
    add_log,
    get_device,
    policy: dict,
    compute_throttled,
) -> None:
    from flask import Response, g, jsonify, request

    enabled = _env_bool("SELF_REGISTER_ENABLED", True)
    auto_approve = _env_bool("SELF_REGISTER_AUTO_APPROVE", True)
    max_devices = max(1, _env_int("SELF_REGISTER_MAX_DEVICES", 3))
    default_priority = os.getenv("SELF_REGISTER_PRIORITY", "low").strip().lower()
    if default_priority not in policy:
        default_priority = "low"
    proxy_port = _env_int("PROXY_PORT", 8888)

    def _caller_lan_ip():
        ip = request.remote_addr or ""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not addr.is_private or addr.is_loopback:
            return None
        return ip

    # ------------------------------------------------------------------ portal
    @app.route("/portal", methods=["GET"])
    def portal():
        return Response(
            PORTAL_HTML,
            mimetype="text/html",
            headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"},
        )

    # ------------------------------------------------------------------ whoami
    @app.route("/api/devices/whoami", methods=["GET"])
    @login_required
    def whoami():
        ip = _caller_lan_ip()
        mac = lookup_mac(ip) if ip else None
        device = None
        if mac:
            row = get_db().execute(
                "SELECT id, user_id FROM devices WHERE mac_address = ?", (mac,)
            ).fetchone()
            if row and (g.user["role"] == "admin" or row["user_id"] == g.user["id"]):
                device = get_device(row["id"])
        return jsonify(
            {
                "success": True,
                "ip": ip,
                "mac": mac,
                "device": device,
                "proxy_port": proxy_port,
                "self_register_enabled": enabled,
                "auto_approve": auto_approve,
            }
        )

    # ------------------------------------------------------------ register-self
    @app.route("/api/devices/register-self", methods=["POST"])
    @login_required
    def register_self():
        if not enabled:
            return jsonify({"success": False, "message": "Self-registration is disabled"}), 403

        ip = _caller_lan_ip()
        if not ip:
            return jsonify({
                "success": False,
                "message": "Open this page from the device you want to register, "
                           "while connected to the Wi-Fi network.",
            }), 400

        mac = lookup_mac(ip)
        if not mac:
            return jsonify({
                "success": False,
                "message": "Could not detect this device's MAC address. Make sure you are on the "
                           "Wi-Fi network directly (and, on iPhone, Private Wi-Fi Address is Off).",
            }), 400

        data = request.get_json(silent=True) or {}
        name = str(data.get("device_name") or "").strip()[:40] or f"{g.user['username']}-device"
        user_id = g.user["id"]

        db = get_db()
        try:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT * FROM devices WHERE mac_address = ?", (mac,)
            ).fetchone()

            if existing is not None:
                if existing["status"] == "blocked":
                    db.rollback()
                    return jsonify({"success": False, "message": "This device is blocked. Contact the admin."}), 403
                if existing["user_id"] not in (None, user_id) and g.user["role"] != "admin":
                    db.rollback()
                    return jsonify({"success": False, "message": "This device is registered to another user."}), 403

                # Previously flagged devices always need an admin decision.
                if existing["status"] == "unauthorized":
                    new_status = "pending"
                else:
                    new_status = existing["status"]
                db.execute(
                    "UPDATE devices SET ip_address = '' WHERE ip_address = ? AND id != ?",
                    (ip, existing["id"]),
                )
                db.execute(
                    """
                    UPDATE devices
                    SET ip_address = ?, user_id = COALESCE(user_id, ?), device_name = ?, status = ?
                    WHERE id = ?
                    """,
                    (ip, user_id, name, new_status, existing["id"]),
                )
                device_id, created = existing["id"], False
            else:
                if g.user["role"] != "admin":
                    count = db.execute(
                        "SELECT COUNT(*) AS c FROM devices WHERE user_id = ?", (user_id,)
                    ).fetchone()["c"]
                    if count >= max_devices:
                        db.rollback()
                        return jsonify({
                            "success": False,
                            "message": f"Device limit reached ({max_devices}). Ask the admin to remove one.",
                        }), 409
                p = policy[default_priority]
                new_status = "trusted" if auto_approve else "pending"
                db.execute(
                    "UPDATE devices SET ip_address = '' WHERE ip_address = ?", (ip,)
                )
                cur = db.execute(
                    """
                    INSERT INTO devices (
                        user_id, ip_address, mac_address, device_name, priority_level,
                        total_quota_mb, used_quota_mb, status, qos_tag, throttled
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                    """,
                    (
                        user_id, ip, mac, name, default_priority, p["quota_mb"],
                        new_status, p["qos_tag"],
                        1 if compute_throttled(default_priority, 0.0, float(p["quota_mb"])) else 0,
                    ),
                )
                device_id, created = cur.lastrowid, True

            add_log(
                f"Device {'registered' if created else 'updated'} by user '{g.user['username']}': "
                f"{name} [{mac}] {ip} status={new_status}",
                db=db,
            )
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            return jsonify({"success": False, "message": "Device already registered"}), 409

        if new_status == "trusted":
            msg = "Device registered. Now set the Wi-Fi proxy to start using the internet."
        else:
            msg = "Device registered — waiting for admin approval before internet access."
        return jsonify(
            {
                "success": True,
                "message": msg,
                "created": created,
                "device": get_device(device_id),
                "proxy_port": proxy_port,
            }
        ), (201 if created else 200)

    # ----------------------------------------------------------------- proxy.pac
    @app.route("/proxy.pac", methods=["GET"])
    def proxy_pac():
        host = request.host.rsplit(":", 1)[0] if ":" in request.host else request.host
        if not _HOST_RE.match(host):  # Host header is client-controlled; keep JS injection-proof
            return Response("Bad host", status=400, mimetype="text/plain")
        body = (
            "function FindProxyForURL(url, host) {\n"
            f'  if (host === "{host}" || isPlainHostName(host) || shExpMatch(host, "*.local")\n'
            '      || isInNet(host, "127.0.0.0", "255.0.0.0")\n'
            '      || isInNet(host, "10.0.0.0", "255.0.0.0")\n'
            '      || isInNet(host, "172.16.0.0", "255.240.0.0")\n'
            '      || isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";\n'
            f'  return "PROXY {host}:{proxy_port}";\n'
            "}\n"
        )
        return Response(
            body,
            mimetype="application/x-ns-proxy-autoconfig",
            headers={"Cache-Control": "no-store"},
        )
