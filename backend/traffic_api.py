"""
Smart WiFi Monitor — live traffic API (additive module, admin only).

    GET /api/traffic/live

Combines three sources into one payload for the dashboard:
  * proxy live counters   -> per-device bytes up/down, speed now, active connections
  * database devices      -> name, status, priority, quota usage
  * OS ARP table          -> devices that are on the hotspot/LAN (even if they
                             are NOT going through the proxy)

Env vars (optional)
-------------------
    HOTSPOT_SUBNET=192.168.137.0/24   which network counts as "connected devices"
    TRAFFIC_ACTIVE_WINDOW_SEC=30      a device is "active" if seen within this window
"""

from __future__ import annotations

import os
import time

from self_register import list_neighbors


def register_traffic_routes(app, proxy, admin_required, list_devices) -> None:
    from flask import jsonify

    subnet = (os.getenv("HOTSPOT_SUBNET") or "192.168.137.0/24").strip()
    try:
        window = max(5, int(os.getenv("TRAFFIC_ACTIVE_WINDOW_SEC", "30")))
    except ValueError:
        window = 30

    @app.route("/api/traffic/live", methods=["GET"])
    @admin_required
    def traffic_live():
        now = time.time()
        snap = proxy.traffic_snapshot(active_window_sec=window)

        devices = list_devices()
        by_ip = {d["ip_address"]: d for d in devices if d.get("ip_address")}
        by_mac = {(d.get("mac_address") or "").upper(): d for d in devices}

        rows = []
        for c in snap["clients"]:
            d = by_ip.get(c["ip"])
            rows.append(
                {
                    "ip": c["ip"],
                    "device_id": d["id"] if d else c["device_id"],
                    "name": (d["device_name"] if d else c["device_name"]) or "Unregistered device",
                    "registered": d is not None,
                    "status": (d["status"] if d else c["status"]) or "unregistered",
                    "priority": d["priority_level"] if d else None,
                    "throttled": bool(d["throttled"]) if d else False,
                    "speed_cap_mbps": d["speed_cap_mbps"] if d else None,
                    "usage_percent": d["usage_percent"] if d else None,
                    "used_quota_mb": d["used_quota_mb"] if d else None,
                    "total_quota_mb": d["total_quota_mb"] if d else None,
                    "down_bytes": c["down"],
                    "up_bytes": c["up"],
                    "rate_down_bps": round(c["rate_down"]),
                    "rate_up_bps": round(c["rate_up"]),
                    "requests": c["requests"],
                    "denied": c["denied"],
                    "active_connections": c["active"],
                    "is_active": c["is_active"],
                    "seconds_since_seen": round(now - c["last_seen"]) if c["last_seen"] else None,
                }
            )
        rows.sort(key=lambda r: (-r["rate_down_bps"], -r["down_bytes"]))

        # Devices on the network that are not going through the proxy right now.
        neighbors = list_neighbors(subnet)
        proxied_ips = {r["ip"] for r in rows if r["is_active"]}
        not_using_proxy = []
        for n in neighbors:
            if n["ip"] in proxied_ips:
                continue
            d = by_mac.get(n["mac"]) or by_ip.get(n["ip"])
            not_using_proxy.append(
                {
                    "ip": n["ip"],
                    "mac": n["mac"],
                    "name": d["device_name"] if d else "Unknown device",
                    "registered": d is not None,
                    "status": d["status"] if d else "unregistered",
                }
            )

        active_now = [r for r in rows if r["is_active"]]
        summary = {
            "proxy_running": snap["running"],
            "devices_active": len(active_now),
            "devices_on_network": len(neighbors),
            "devices_registered": len(devices),
            "devices_not_using_proxy": len(not_using_proxy),
            "active_connections": snap["active_connections"],
            "rate_down_bps": sum(r["rate_down_bps"] for r in rows),
            "rate_up_bps": sum(r["rate_up_bps"] for r in rows),
            "down_bytes": sum(r["down_bytes"] for r in rows),
            "up_bytes": sum(r["up_bytes"] for r in rows),
            "total_requests": snap["total_requests"],
            "rejected_requests": snap["rejected_requests"],
            "since": snap["started_at"],
            "hotspot_subnet": subnet,
        }
        return jsonify(
            {
                "success": True,
                "time": now,
                "summary": summary,
                "devices": rows,
                "not_using_proxy": not_using_proxy,
                "history": snap["history"],
            }
        )
