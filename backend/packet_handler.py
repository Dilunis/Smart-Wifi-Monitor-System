"""
Smart WiFi Monitor — packet handling module (additive, no existing feature changed).

What it does
------------
1. Sniffs packets (scapy) on a chosen interface in a background thread.
2. Attributes bytes to devices by MAC (uplink = src MAC, downlink = dst MAC).
3. Every PACKET_FLUSH_SEC seconds, flushes the counters to SQLite in ONE
   transaction: updates used_quota_mb, throttled, ip_address (uses your existing
   compute_throttled policy) and writes quota alerts to activity_logs.
4. Optionally auto-discovers unknown local devices and registers them as
   'unauthorized' (rate-capped, so spoofed MAC floods can't fill the DB).
5. Exposes admin-only endpoints: /api/packets/stats, /start, /stop.

Requirements
------------
    pip install scapy
    Run the backend with capture privileges (root / CAP_NET_RAW on Linux,
    Npcap installed + admin on Windows), and see the note on Wi-Fi visibility below.

Env vars (all optional)
-----------------------
    PACKET_CAPTURE_ENABLED=1        start capture automatically on boot
    PACKET_IFACE=wlan0              interface (default: scapy default)
    PACKET_BPF="ip or arp"          BPF filter (default "ip or arp")
    PACKET_FLUSH_SEC=5              DB flush interval
    PACKET_AUTO_DISCOVER=1          register unknown local devices as unauthorized
    PACKET_MAX_DISCOVER_PER_FLUSH=10
    PACKET_SUBNET=192.168.1.0/24    only discover/attribute IPs inside this subnet
    PACKET_GATEWAY_IP=192.168.1.1   never register the gateway as a device
    PACKET_IGNORE_MACS=aa:bb:...,   comma-separated MACs to ignore entirely

Note: a normal Wi-Fi client only sees its own traffic. To see every device you must
run this on the router/gateway/AP, or on a host whose interface is a bridge/mirror
port (or in monitor mode). Traffic between two local devices is counted for both.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import threading
import time
from collections import defaultdict
from typing import Callable

log = logging.getLogger("smart-wifi-monitor.packets")

try:  # scapy is optional; the API keeps working without it
    from scapy.all import ARP, Ether, IP, AsyncSniffer  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:  # noqa: BLE001
    SCAPY_AVAILABLE = False

_MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
_BYTES_PER_MB = 1024 * 1024


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _is_unicast(mac: str) -> bool:
    """Reject broadcast/multicast/null MACs (multicast bit = LSB of first octet)."""
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return not (first & 1) and mac != "00:00:00:00:00:00"


class PacketMonitor:
    def __init__(
        self,
        db_factory: Callable,
        compute_throttled: Callable[[str, float, float], bool],
        add_log: Callable,
        policy: dict,
    ):
        self._db_factory = db_factory
        self._compute_throttled = compute_throttled
        self._add_log = add_log
        self._policy = policy

        self.iface = os.getenv("PACKET_IFACE") or None
        self.bpf = os.getenv("PACKET_BPF", "ip or arp")
        self.flush_sec = _env_int("PACKET_FLUSH_SEC", 5)
        self.auto_discover = _env_bool("PACKET_AUTO_DISCOVER", True)
        self.max_discover = _env_int("PACKET_MAX_DISCOVER_PER_FLUSH", 10)
        self.gateway_ip = (os.getenv("PACKET_GATEWAY_IP") or "").strip()
        self.ignore_macs = {
            m.strip().upper()
            for m in (os.getenv("PACKET_IGNORE_MACS") or "").split(",")
            if m.strip()
        }
        subnet = (os.getenv("PACKET_SUBNET") or "").strip()
        try:
            self.subnet = ipaddress.ip_network(subnet, strict=False) if subnet else None
        except ValueError:
            log.warning("Invalid PACKET_SUBNET=%r — ignoring", subnet)
            self.subnet = None

        self._lock = threading.Lock()
        self._bytes: dict[str, int] = defaultdict(int)
        self._ips: dict[str, str] = {}
        self._sniffer = None
        self._flusher: threading.Thread | None = None
        self._stop_evt = threading.Event()
        self._running = False

        # stats
        self.packets_seen = 0
        self.bytes_seen = 0
        self.last_flush: float | None = None
        self.last_error: str | None = None
        self.started_at: float | None = None

    # ------------------------------------------------------------------ capture
    def _is_local_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if ip == self.gateway_ip:
            return False
        if self.subnet is not None:
            return addr in self.subnet
        return addr.is_private and not addr.is_multicast and not addr.is_loopback

    def _on_packet(self, pkt) -> None:
        """Hot path: keep it tiny. Only touches in-memory counters."""
        try:
            if not pkt.haslayer(Ether):
                return
            eth = pkt[Ether]
            src, dst = eth.src.upper(), eth.dst.upper()
            size = len(pkt)

            with self._lock:
                self.packets_seen += 1
                self.bytes_seen += size
                if src != dst:
                    if _is_unicast(src) and src not in self.ignore_macs:
                        self._bytes[src] += size
                    if _is_unicast(dst) and dst not in self.ignore_macs:
                        self._bytes[dst] += size

                # Remember MAC -> IP (source side only; that's who owns the IP)
                if pkt.haslayer(IP):
                    ip = pkt[IP].src
                    if self._is_local_ip(ip):
                        self._ips[src] = ip
                elif pkt.haslayer(ARP):
                    arp = pkt[ARP]
                    mac = str(arp.hwsrc).upper()
                    ip = str(arp.psrc)
                    if _is_unicast(mac) and self._is_local_ip(ip):
                        self._ips[mac] = ip
        except Exception as exc:  # noqa: BLE001 - never let the sniffer thread die
            self.last_error = f"packet handler: {exc}"

    # ------------------------------------------------------------------ flushing
    def flush(self) -> int:
        """Write accumulated counters to the DB. Returns number of devices updated."""
        with self._lock:
            if not self._bytes:
                self.last_flush = time.time()
                return 0
            bytes_map, ip_map = self._bytes, self._ips
            self._bytes, self._ips = defaultdict(int), {}

        updated = 0
        discovered = 0
        conn = self._db_factory()
        try:
            for mac, nbytes in bytes_map.items():
                row = conn.execute(
                    "SELECT * FROM devices WHERE mac_address = ?", (mac,)
                ).fetchone()
                ip = ip_map.get(mac)

                if row is None:
                    if (
                        self.auto_discover
                        and ip
                        and discovered < self.max_discover
                        and _MAC_RE.match(mac)
                        and self._discover(conn, mac, ip, nbytes)
                    ):
                        discovered += 1
                    continue

                total = float(row["total_quota_mb"])
                before = float(row["used_quota_mb"])
                used = min(before + nbytes / _BYTES_PER_MB, total)
                throttled = self._compute_throttled(row["priority_level"], used, total)

                conn.execute(
                    """
                    UPDATE devices
                    SET used_quota_mb = ?, throttled = ?, ip_address = ?
                    WHERE id = ?
                    """,
                    (used, 1 if throttled else 0, ip or row["ip_address"], row["id"]),
                )
                updated += 1

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
            log.warning("Packet flush failed: %s", exc)
        finally:
            conn.close()
            self.last_flush = time.time()
        return updated

    def _discover(self, conn, mac: str, ip: str, nbytes: int) -> bool:
        low = self._policy["low"]
        name = "Unknown-" + mac[-8:].replace(":", "")
        used = min(nbytes / _BYTES_PER_MB, float(low["quota_mb"]))
        try:
            conn.execute(
                """
                INSERT INTO devices (
                    user_id, ip_address, mac_address, device_name, priority_level,
                    total_quota_mb, used_quota_mb, status, qos_tag, throttled
                ) VALUES (NULL, ?, ?, ?, 'low', ?, ?, 'unauthorized', ?, 0)
                """,
                (ip, mac, name, low["quota_mb"], used, low["qos_tag"]),
            )
            self._add_log(f"Unknown device detected on network: {mac} ({ip})", db=conn)
            return True
        except Exception as exc:  # noqa: BLE001 - e.g. UNIQUE race
            self.last_error = f"discover: {exc}"
            return False

    def _flush_loop(self) -> None:
        while not self._stop_evt.wait(self.flush_sec):
            self.flush()
        self.flush()  # final drain

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> tuple[bool, str]:
        if self._running:
            return True, "Packet capture already running"
        if not SCAPY_AVAILABLE:
            return False, "scapy is not installed (pip install scapy)"
        try:
            self._sniffer = AsyncSniffer(
                iface=self.iface,
                prn=self._on_packet,
                store=False,
                filter=self.bpf or None,
            )
            self._sniffer.start()
        except PermissionError:
            return False, "Insufficient privileges for packet capture (need root/admin)"
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"start: {exc}"
            return False, f"Could not start capture: {exc}"

        self._stop_evt.clear()
        self._flusher = threading.Thread(
            target=self._flush_loop, daemon=True, name="packet-flush"
        )
        self._flusher.start()
        self._running = True
        self.started_at = time.time()
        log.info("Packet capture started iface=%s filter=%r", self.iface or "default", self.bpf)
        return True, "Packet capture started"

    def stop(self) -> tuple[bool, str]:
        if not self._running:
            return True, "Packet capture not running"
        try:
            if self._sniffer is not None:
                self._sniffer.stop()
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"stop: {exc}"
        self._stop_evt.set()
        if self._flusher is not None:
            self._flusher.join(timeout=self.flush_sec + 5)
        self._running = False
        self._sniffer = None
        log.info("Packet capture stopped")
        return True, "Packet capture stopped"

    @property
    def running(self) -> bool:
        return self._running

    def stats(self) -> dict:
        with self._lock:
            pending = len(self._bytes)
        return {
            "scapy_available": SCAPY_AVAILABLE,
            "running": self._running,
            "iface": self.iface or "default",
            "bpf_filter": self.bpf,
            "flush_interval_sec": self.flush_sec,
            "auto_discover": self.auto_discover,
            "packets_seen": self.packets_seen,
            "bytes_seen": self.bytes_seen,
            "pending_devices": pending,
            "started_at": self.started_at,
            "last_flush": self.last_flush,
            "last_error": self.last_error,
        }


# ---------------------------------------------------------------------- routes
def register_packet_routes(app, monitor: PacketMonitor, admin_required) -> None:
    from flask import jsonify

    @app.route("/api/packets/stats", methods=["GET"])
    @admin_required
    def packet_stats():
        return jsonify({"success": True, "stats": monitor.stats()})

    @app.route("/api/packets/start", methods=["POST"])
    @admin_required
    def packet_start():
        ok, msg = monitor.start()
        return jsonify({"success": ok, "message": msg, "stats": monitor.stats()}), (
            200 if ok else 500
        )

    @app.route("/api/packets/stop", methods=["POST"])
    @admin_required
    def packet_stop():
        ok, msg = monitor.stop()
        return jsonify({"success": ok, "message": msg, "stats": monitor.stats()})
