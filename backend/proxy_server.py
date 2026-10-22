"""
Smart WiFi Monitor — enforcing forward proxy (additive module).

Devices on your network set their Wi-Fi HTTP proxy to  <this-computer-IP>:8888.
Every request then flows through this proxy, which can:

  * identify the device by client IP (matched to devices.ip_address)
  * reject blocked / unauthorized / unregistered devices
  * count real bytes (up + down) into used_quota_mb
  * reject devices whose quota is exhausted (non-high tiers)
  * throttle throttled devices to PRIORITY_POLICY[...]["speed_cap_mbps"]

HTTP is proxied normally. HTTPS uses CONNECT tunnelling: bytes are counted and
forwarded, but NEVER decrypted or inspected.

Env vars (all optional)
-----------------------
    PROXY_ENABLED=1              start automatically on boot
    PROXY_HOST=0.0.0.0           bind address (0.0.0.0 = reachable from the LAN)
    PROXY_PORT=8888
    PROXY_FLUSH_SEC=5            DB flush interval
    PROXY_ALLOW_UNAUTHORIZED=0   1 = let unauthorized/pending/unknown devices through
    PROXY_CONNECT_PORTS=443,8443 ports allowed for HTTPS tunnels
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import threading
import time
from collections import deque
from urllib.parse import urlsplit

log = logging.getLogger("smart-wifi-monitor.proxy")

_MB = 1024 * 1024
_HOP_HEADERS = {b"proxy-connection", b"proxy-authorization", b"connection", b"keep-alive"}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    return default if raw is None else raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


class ProxyServer:
    def __init__(self, db_factory, compute_throttled, add_log, policy, *, allow_loopback_dest=False):
        self._db_factory = db_factory
        self._compute_throttled = compute_throttled
        self._add_log = add_log
        self._policy = policy

        self.host = os.getenv("PROXY_HOST", "0.0.0.0")
        self.port = _env_int("PROXY_PORT", 8888)
        self.flush_sec = max(1, _env_int("PROXY_FLUSH_SEC", 5))
        self.allow_unauthorized = _env_bool("PROXY_ALLOW_UNAUTHORIZED", False)
        self.connect_ports = {
            int(p) for p in os.getenv("PROXY_CONNECT_PORTS", "443,8443").split(",") if p.strip().isdigit()
        }
        self.allow_loopback_dest = allow_loopback_dest  # tests only; keep False

        # Event-loop-thread state
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server = None
        self._stop_future: asyncio.Future | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._start_error: str | None = None
        self._running = False

        self._pending: dict[int, int] = {}       # device_id -> bytes not yet flushed
        self._next_free: dict[int, float] = {}   # device_id -> pacing clock (throttle)
        self._cache: dict[str, dict] = {}        # client ip -> device row snapshot
        self._cache_ts = 0.0
        self._cache_lock: asyncio.Lock | None = None
        self._last_block_log: dict[tuple, float] = {}
        self._traffic: dict[str, dict] = {}       # client ip -> live traffic counters
        self._history: deque = deque(maxlen=120)  # 1-second samples of total throughput

        # stats
        self.total_connections = 0
        self.active_connections = 0
        self.rejected = 0
        self.bytes_total = 0
        self.started_at: float | None = None
        self.last_error: str | None = None

    # ------------------------------------------------------------- device lookup
    def _refresh_cache(self) -> None:
        conn = self._db_factory()
        try:
            rows = conn.execute(
                "SELECT * FROM devices WHERE ip_address IS NOT NULL AND ip_address != ''"
            ).fetchall()
            self._cache = {r["ip_address"]: dict(r) for r in rows}
            self._cache_ts = time.monotonic()
        finally:
            conn.close()

    async def _device_for(self, ip: str):
        if time.monotonic() - self._cache_ts > 5:
            async with self._cache_lock:
                if time.monotonic() - self._cache_ts > 5:
                    await asyncio.get_running_loop().run_in_executor(None, self._refresh_cache)
        return self._cache.get(ip)

    def _live_used(self, dev) -> float:
        return float(dev["used_quota_mb"]) + self._pending.get(dev["id"], 0) / _MB

    def _reject_reason(self, dev) -> str | None:
        if dev is None:
            return None if self.allow_unauthorized else "Device not registered"
        if dev["status"] == "blocked":
            return "Device is blocked"
        if dev["status"] in ("unauthorized", "pending") and not self.allow_unauthorized:
            return "Device not authorized"
        if dev["priority_level"] != "high" and self._live_used(dev) >= float(dev["total_quota_mb"]):
            return "Data quota exhausted"
        return None

    def _log_block(self, ip: str, dev, reason: str) -> None:
        """Rate-limited (1/min per ip+reason) so a retrying client can't flood the log."""
        key = (ip, reason)
        now = time.monotonic()
        if now - self._last_block_log.get(key, 0) < 60:
            return
        self._last_block_log[key] = now
        name = dev["device_name"] if dev else "unknown"
        threading.Thread(
            target=self._write_log, args=(f"Proxy denied {name} ({ip}): {reason}",), daemon=True
        ).start()

    def _write_log(self, msg: str) -> None:
        conn = self._db_factory()
        try:
            self._add_log(msg, db=conn)
            conn.commit()
        finally:
            conn.close()

    # ---------------------------------------------------------------- throttling
    async def _throttle(self, dev, nbytes: int) -> None:
        priority = dev["priority_level"]
        cap = self._policy.get(priority, {}).get("speed_cap_mbps")
        if not cap:
            return
        if not self._compute_throttled(priority, self._live_used(dev), float(dev["total_quota_mb"])):
            return
        rate = cap * 125_000  # Mbps -> bytes/sec
        loop = asyncio.get_running_loop()
        now = loop.time()
        slot = max(self._next_free.get(dev["id"], now), now)
        self._next_free[dev["id"]] = slot + nbytes / rate
        if slot > now:
            await asyncio.sleep(slot - now)

    # ------------------------------------------------------------------- piping
    async def _pipe(self, reader, writer, dev, st, direction) -> None:
        try:
            while True:
                data = await reader.read(16384)
                if not data:
                    break
                if dev is not None:
                    if self._reject_reason(dev) is not None:
                        break  # blocked / quota exhausted mid-stream
                    await self._throttle(dev, len(data))
                writer.write(data)
                await writer.drain()
                n = len(data)
                self.bytes_total += n
                st[direction] += n          # direction: "up" (device -> internet) / "down"
                st["last_seen"] = time.time()
                if dev is not None:
                    self._pending[dev["id"]] = self._pending.get(dev["id"], 0) + n
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    async def _reply(writer, code: int, text: str) -> None:
        body = text.encode()
        writer.write(
            f"HTTP/1.1 {code} {text}\r\nContent-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
        )
        try:
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ handler
    async def _handle(self, cr, cw) -> None:
        self.total_connections += 1
        self.active_connections += 1
        uw = None
        st = None
        counted = False
        try:
            peer = cw.get_extra_info("peername") or ("?", 0)
            ip = peer[0]
            try:
                head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 15)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
                return

            dev = await self._device_for(ip)
            st = self._tstat(ip, dev)
            st["last_seen"] = time.time()
            reason = self._reject_reason(dev)
            if reason:
                st["denied"] += 1
                self.rejected += 1
                self._log_block(ip, dev, reason)
                await self._reply(cw, 403, reason)
                return

            st["requests"] += 1
            st["active"] += 1
            counted = True

            lines = head.split(b"\r\n")
            try:
                method, target, version = lines[0].decode("latin-1").split(" ", 2)
            except ValueError:
                await self._reply(cw, 400, "Bad request")
                return

            if method.upper() == "CONNECT":
                host, _, port_s = target.rpartition(":")
                if not host or not port_s.isdigit() or int(port_s) not in self.connect_ports:
                    await self._reply(cw, 403, "CONNECT port not allowed")
                    return
                host, port, path = host.strip("[]"), int(port_s), None
            else:
                u = urlsplit(target)
                if u.scheme != "http" or not u.hostname:
                    await self._reply(cw, 400, "Only absolute http:// URLs are proxied")
                    return
                host, port = u.hostname, u.port or 80
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")

            try:
                ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
            except (OSError, asyncio.TimeoutError):
                await self._reply(cw, 502, "Bad gateway")
                return

            # Don't let LAN clients reach services on this computer (e.g. the Flask API)
            if not self.allow_loopback_dest:
                try:
                    dest = ipaddress.ip_address((uw.get_extra_info("peername") or ("",))[0])
                    if dest.is_loopback or dest.is_link_local or dest.is_unspecified:
                        await self._reply(cw, 403, "Destination not allowed")
                        return
                except ValueError:
                    pass

            if path is None:
                cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await cw.drain()
            else:
                kept = [
                    ln for ln in lines[1:]
                    if ln and ln.split(b":", 1)[0].strip().lower() not in _HOP_HEADERS
                ]
                new_head = (
                    f"{method} {path} {version}".encode("latin-1")
                    + b"\r\n" + b"\r\n".join(kept) + b"\r\nConnection: close\r\n\r\n"
                )
                uw.write(new_head)
                await uw.drain()

            t1 = asyncio.create_task(self._pipe(cr, uw, dev, st, "up"))     # device -> internet
            t2 = asyncio.create_task(self._pipe(ur, cw, dev, st, "down"))   # internet -> device
            _, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            await asyncio.gather(t1, t2, return_exceptions=True)
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"handler: {exc}"
        finally:
            self.active_connections -= 1
            if counted and st is not None:
                st["active"] = max(0, st["active"] - 1)
            for w in (cw, uw):
                try:
                    if w is not None:
                        w.close()
                except Exception:  # noqa: BLE001
                    pass

    # ------------------------------------------------------------------ flushing
    def _flush_db(self, snapshot: dict[int, int]) -> None:
        conn = self._db_factory()
        try:
            for dev_id, nbytes in snapshot.items():
                row = conn.execute("SELECT * FROM devices WHERE id = ?", (dev_id,)).fetchone()
                if row is None:
                    continue
                total, before = float(row["total_quota_mb"]), float(row["used_quota_mb"])
                used = min(before + nbytes / _MB, total)
                throttled = self._compute_throttled(row["priority_level"], used, total)
                conn.execute(
                    "UPDATE devices SET used_quota_mb = ?, throttled = ? WHERE id = ?",
                    (used, 1 if throttled else 0, dev_id),
                )
                if total > 0:
                    r0, r1 = before / total, used / total
                    if r0 < 1.0 <= r1:
                        self._add_log(f"Quota exhausted: {row['device_name']}", db=conn)
                    elif r0 < 0.9 <= r1:
                        self._add_log(f"Quota critical (≥90%): {row['device_name']}", db=conn)
            conn.commit()
        except Exception as exc:  # noqa: BLE001
            conn.rollback()
            self.last_error = f"flush: {exc}"
            log.warning("Proxy flush failed: %s", exc)
        finally:
            conn.close()

    async def _flush_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            await asyncio.sleep(self.flush_sec)
            await self._flush_once(loop)

    async def _flush_once(self, loop) -> None:
        if not self._pending:
            return
        snapshot, self._pending = self._pending, {}
        await loop.run_in_executor(None, self._flush_db, snapshot)
        self._cache_ts = 0.0  # force fresh usage numbers on next lookup

    # ------------------------------------------------------------ live traffic
    def _tstat(self, ip: str, dev) -> dict:
        st = self._traffic.get(ip)
        if st is None:
            if len(self._traffic) >= 1000:  # keep memory bounded
                oldest = min(self._traffic, key=lambda k: self._traffic[k]["last_seen"])
                self._traffic.pop(oldest, None)
            st = {
                "ip": ip, "device_id": None, "device_name": None, "status": None,
                "up": 0, "down": 0, "requests": 0, "denied": 0, "active": 0,
                "last_seen": 0.0, "rate_up": 0.0, "rate_down": 0.0, "_p_up": 0, "_p_down": 0,
            }
            self._traffic[ip] = st
        if dev is not None:
            st["device_id"] = dev["id"]
            st["device_name"] = dev["device_name"]
            st["status"] = dev["status"]
        return st

    async def _rate_loop(self) -> None:
        """Every second: turn byte counters into smoothed bytes/sec per client + total."""
        while True:
            await asyncio.sleep(1)
            tot_up = tot_down = 0.0
            for st in list(self._traffic.values()):
                du, dd = st["up"] - st["_p_up"], st["down"] - st["_p_down"]
                st["_p_up"], st["_p_down"] = st["up"], st["down"]
                st["rate_up"] = 0.5 * du + 0.5 * st["rate_up"]
                st["rate_down"] = 0.5 * dd + 0.5 * st["rate_down"]
                if st["rate_up"] < 1:
                    st["rate_up"] = 0.0
                if st["rate_down"] < 1:
                    st["rate_down"] = 0.0
                tot_up += st["rate_up"]
                tot_down += st["rate_down"]
            self._history.append({"t": int(time.time()), "up": tot_up, "down": tot_down})

    def traffic_snapshot(self, active_window_sec: int = 30) -> dict:
        """Thread-safe copy of live traffic for the API (bytes and bytes/sec)."""
        now = time.time()
        clients = []
        for st in list(self._traffic.values()):
            c = {k: v for k, v in st.items() if not k.startswith("_p_")}
            c["is_active"] = c["active"] > 0 or (now - c["last_seen"]) <= active_window_sec
            clients.append(c)
        return {
            "running": self._running,
            "started_at": self.started_at,
            "clients": clients,
            "history": list(self._history),
            "total_requests": self.total_connections,
            "active_connections": self.active_connections,
            "rejected_requests": self.rejected,
            "bytes_total": self.bytes_total,
        }

    # ---------------------------------------------------------------- lifecycle
    async def _serve(self) -> None:
        self._cache_lock = asyncio.Lock()
        self._stop_future = asyncio.get_running_loop().create_future()
        try:
            self._server = await asyncio.start_server(self._handle, self.host, self.port)
        except OSError as exc:
            self._start_error = f"Cannot bind {self.host}:{self.port} — {exc}"
            self._ready.set()
            return
        flusher = asyncio.create_task(self._flush_loop())
        rater = asyncio.create_task(self._rate_loop())
        self._ready.set()
        await self._stop_future
        flusher.cancel()
        rater.cancel()
        self._server.close()
        await self._server.wait_closed()
        await self._flush_once(asyncio.get_running_loop())

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        finally:
            self._loop.close()

    def start(self) -> tuple[bool, str]:
        if self._running:
            return True, "Proxy already running"
        self._ready.clear()
        self._start_error = None
        self._thread = threading.Thread(target=self._run, daemon=True, name="proxy-server")
        self._thread.start()
        self._ready.wait(timeout=5)
        if self._start_error:
            self.last_error = self._start_error
            return False, self._start_error
        self._running = True
        self.started_at = time.time()
        log.info("Proxy listening on %s:%s", self.host, self.port)
        return True, f"Proxy started on {self.host}:{self.port}"

    def stop(self) -> tuple[bool, str]:
        if not self._running:
            return True, "Proxy not running"
        if self._loop and self._stop_future:
            self._loop.call_soon_threadsafe(
                lambda: self._stop_future.done() or self._stop_future.set_result(True)
            )
        if self._thread:
            self._thread.join(timeout=10)
        self._running = False
        log.info("Proxy stopped")
        return True, "Proxy stopped"

    @property
    def running(self) -> bool:
        return self._running

    def stats(self) -> dict:
        return {
            "running": self._running,
            "listen": f"{self.host}:{self.port}",
            "total_connections": self.total_connections,
            "active_connections": self.active_connections,
            "rejected_requests": self.rejected,
            "bytes_total": self.bytes_total,
            "pending_flush_devices": len(self._pending),
            "allow_unauthorized": self.allow_unauthorized,
            "started_at": self.started_at,
            "last_error": self.last_error,
        }


def register_proxy_routes(app, proxy: ProxyServer, admin_required) -> None:
    from flask import jsonify

    @app.route("/api/proxy/stats", methods=["GET"])
    @admin_required
    def proxy_stats():
        return jsonify({"success": True, "stats": proxy.stats()})

    @app.route("/api/proxy/start", methods=["POST"])
    @admin_required
    def proxy_start():
        ok, msg = proxy.start()
        return jsonify({"success": ok, "message": msg, "stats": proxy.stats()}), (200 if ok else 500)

    @app.route("/api/proxy/stop", methods=["POST"])
    @admin_required
    def proxy_stop():
        ok, msg = proxy.stop()
        return jsonify({"success": ok, "message": msg, "stats": proxy.stats()})
