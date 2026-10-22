"""
Smart WiFi Monitor — Flask API
Priority / quota policy engine, role-based auth, and request notifications.
Phase 1 hardened: session TTL, encrypted secrets, WAL, atomic writes, async mail.
Phase 2: packet capture (packet_handler.py) and enforcing proxy (proxy_server.py).
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import Flask, Response, g, jsonify, request
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

# NEW: packet handling + proxy modules (must be in the same folder as app.py)
from packet_handler import PacketMonitor, register_packet_routes
from proxy_server import ProxyServer, register_proxy_routes
from self_register import register_self_service_routes
from traffic_api import register_traffic_routes

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("smart-wifi-monitor")

BASE_DIR = Path(__file__).resolve().parent
DATABASE = str(BASE_DIR / "network_monitor.db")
RUNTIME_SECRET_FILE = BASE_DIR / ".runtime_secret"


def _resolve_secret_key() -> str:
    """Use env, else persisted auto-key, else generate (no .env required)."""
    env_key = (os.getenv("FLASK_SECRET_KEY") or "").strip()
    if env_key and env_key != "dev-secret-change-me":
        return env_key
    if env_key == "dev-secret-change-me":
        log.warning(
            "FLASK_SECRET_KEY is the insecure default — set a strong value in .env for production."
        )
        return env_key
    if RUNTIME_SECRET_FILE.exists():
        stored = RUNTIME_SECRET_FILE.read_text(encoding="utf-8").strip()
        if stored:
            log.warning(
                "FLASK_SECRET_KEY not set — using auto-generated key from %s",
                RUNTIME_SECRET_FILE.name,
            )
            return stored
    generated = secrets.token_urlsafe(48)
    try:
        RUNTIME_SECRET_FILE.write_text(generated, encoding="utf-8")
        log.warning(
            "FLASK_SECRET_KEY / FERNET_KEY not set — generated ephemeral key and saved to %s "
            "(set FLASK_SECRET_KEY in .env for production).",
            RUNTIME_SECRET_FILE.name,
        )
    except OSError:
        log.warning(
            "FLASK_SECRET_KEY not set — using in-memory ephemeral key for this process only."
        )
    return generated


SECRET_KEY = _resolve_secret_key()
# Prefer explicit FERNET_KEY; otherwise derive from SECRET_KEY
if not (os.getenv("FERNET_KEY") or "").strip():
    log.warning(
        "FERNET_KEY not set — deriving encryption key from FLASK_SECRET_KEY / auto-secret."
    )

ALLOWED_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if o.strip()
]
# Back-compat single origin
_single = (os.getenv("FRONTEND_ORIGIN") or "").strip()
if _single and _single not in ALLOWED_ORIGINS:
    ALLOWED_ORIGINS.append(_single)

SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "8"))
LOGIN_RATE_LIMIT = int(os.getenv("LOGIN_RATE_LIMIT", "10"))
LOGIN_RATE_WINDOW_SEC = int(os.getenv("LOGIN_RATE_WINDOW_SEC", "300"))

MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
VALID_SECURITY_TYPES = {
    "WPA2-PSK",
    "WPA3-Personal",
    # Legacy labels still accepted and normalized on read
    "WPA2",
    "WPA3",
    "WPA2/WPA3",
}

SECURITY_TYPE_ALIASES = {
    "WPA2": "WPA2-PSK",
    "WPA3": "WPA3-Personal",
    "WPA2/WPA3": "WPA3-Personal",
}

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
CORS(
    app,
    resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=True,
)

# ---------------------------------------------------------------------------
# Priority & quota policy
# ---------------------------------------------------------------------------
PRIORITY_POLICY = {
    "high": {
        "quota_mb": 50 * 1024,
        "qos_tag": "Voice/Video/Mission-Critical",
        "throttle_at_ratio": None,
        "speed_cap_mbps": None,
        "auto_renew_on_admin_approval": True,
        "usage_rate_mb_per_tick": 12,
    },
    "medium": {
        "quota_mb": 20 * 1024,
        "qos_tag": "Standard",
        "throttle_at_ratio": 0.90,
        "speed_cap_mbps": 50,
        "auto_renew_on_admin_approval": False,
        "usage_rate_mb_per_tick": 6,
    },
    "low": {
        "quota_mb": 5 * 1024,
        "qos_tag": "Capped/IoT",
        "throttle_at_ratio": 0.0,
        "speed_cap_mbps": 10,
        "auto_renew_on_admin_approval": False,
        "usage_rate_mb_per_tick": 2,
    },
}

VALID_PRIORITIES = set(PRIORITY_POLICY.keys())
VALID_DEVICE_STATUSES = {"trusted", "unauthorized", "blocked", "pending"}
# Admin-selectable custom quota sizes (GB) for a device, independent of its priority tier.
VALID_QUOTA_GB = {1, 2, 3, 4, 5, 6, 7, 8, 10}

# Fixed dummy hash so missing-user logins take a similar check path (no user enum timing)
_DUMMY_PASSWORD_HASH = generate_password_hash("invalid-login-placeholder")

# In-memory login rate limiter: ip -> deque of attempt timestamps
_login_attempts: dict[str, deque[float]] = defaultdict(deque)
_login_lock = threading.Lock()

# Lightweight TTL caches (process-local)
_CACHE_LOCK = threading.Lock()
_POLICY_PAYLOAD_CACHE: dict | None = None
_ROUTER_CACHE: dict = {"data": None, "ts": 0.0}
_ROUTER_CACHE_TTL_SEC = 30.0


# ---------------------------------------------------------------------------
# Crypto helpers (Wi-Fi secrets at rest)
# ---------------------------------------------------------------------------
def _fernet() -> Fernet:
    raw = os.getenv("FERNET_KEY") or SECRET_KEY
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plain: str | None) -> str:
    if not plain:
        return ""
    return _fernet().encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_secret(token: str | None) -> str:
    """Decrypt Fernet token; treat legacy plaintext as-is."""
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError):
        return token


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def configure_connection(conn: sqlite3.Connection) -> sqlite3.Connection:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA cache_size = -64000")  # ~64MB page cache
    conn.execute("PRAGMA temp_store = MEMORY")
    return conn


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DATABASE, timeout=30.0)
        g.db = configure_connection(conn)
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def row_to_dict(row):
    return dict(row) if row is not None else None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_str() -> str:
    return utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # Stored as "YYYY-MM-DD HH:MM:SS UTC"
        cleaned = value.replace(" UTC", "").strip()
        return datetime.strptime(cleaned, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def session_expiry_str() -> str:
    return (utc_now() + timedelta(hours=SESSION_TTL_HOURS)).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def cleanup_expired_sessions(db: sqlite3.Connection | None = None) -> int:
    conn = db or get_db()
    cur = conn.execute(
        "DELETE FROM sessions WHERE expires_at IS NOT NULL AND expires_at < ?",
        (utc_now_str(),),
    )
    if db is None:
        conn.commit()
    return cur.rowcount


def migrate_schema(cur: sqlite3.Cursor):
    session_cols = {r[1] for r in cur.execute("PRAGMA table_info(sessions)").fetchall()}
    if "expires_at" not in session_cols:
        cur.execute("ALTER TABLE sessions ADD COLUMN expires_at TEXT")

    # Hot-path indexes (IF NOT EXISTS is safe on every boot)
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id)"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_requests_status ON priority_requests(status)"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_requests_user ON priority_requests(user_id)"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)"
    )

    # Normalize legacy Wi-Fi security labels
    cur.execute(
        "UPDATE router_settings SET security_type = 'WPA3-Personal' "
        "WHERE security_type IN ('WPA3', 'WPA2/WPA3')"
    )
    cur.execute(
        "UPDATE router_settings SET security_type = 'WPA2-PSK' "
        "WHERE security_type = 'WPA2'"
    )


def init_db():
    db = configure_connection(sqlite3.connect(DATABASE, timeout=30.0))
    cur = db.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            email TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            ip_address TEXT,
            mac_address TEXT NOT NULL UNIQUE,
            device_name TEXT NOT NULL,
            priority_level TEXT NOT NULL DEFAULT 'medium'
                CHECK(priority_level IN ('high', 'medium', 'low')),
            total_quota_mb REAL NOT NULL,
            used_quota_mb REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'trusted'
                CHECK(status IN ('trusted', 'unauthorized', 'blocked', 'pending')),
            qos_tag TEXT,
            throttled INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS priority_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            requested_priority TEXT NOT NULL
                CHECK(requested_priority IN ('high', 'medium', 'low')),
            reason TEXT,
            duration_hours INTEGER,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'approved', 'rejected')),
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS router_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            wifi_name TEXT NOT NULL,
            wifi_password TEXT,
            security_type TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )

    migrate_schema(cur)

    if cur.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
            (
                "admin",
                generate_password_hash("Admin@123"),
                "admin",
                os.getenv("ADMIN_NOTIFY_EMAIL", "admin@example.com"),
            ),
        )
        cur.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
            ("client", generate_password_hash("Client@123"), "user", "client@example.com"),
        )
        cur.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
            ("guest", generate_password_hash("Guest@123"), "user", "guest@example.com"),
        )

    client = cur.execute(
        "SELECT id FROM users WHERE username = ?", ("client",)
    ).fetchone()
    guest = cur.execute(
        "SELECT id FROM users WHERE username = ?", ("guest",)
    ).fetchone()

    if cur.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"] == 0:
        seed_devices = [
            (
                client["id"],
                "192.168.1.10",
                "00:A0:C9:14:C8:29",
                "Client-Laptop",
                "medium",
                PRIORITY_POLICY["medium"]["quota_mb"],
                4200.0,
                "trusted",
                PRIORITY_POLICY["medium"]["qos_tag"],
            ),
            (
                client["id"],
                "192.168.1.15",
                "00:A0:C9:55:B2:11",
                "Client-Phone",
                "high",
                PRIORITY_POLICY["high"]["quota_mb"],
                8100.0,
                "trusted",
                PRIORITY_POLICY["high"]["qos_tag"],
            ),
            (
                guest["id"],
                "192.168.1.40",
                "00:A0:C9:22:33:44",
                "Guest-Tablet",
                "low",
                PRIORITY_POLICY["low"]["quota_mb"],
                1200.0,
                "trusted",
                PRIORITY_POLICY["low"]["qos_tag"],
            ),
            (
                None,
                "192.168.1.99",
                "00:A0:C9:FF:E4:AA",
                "Unknown-Intruder",
                "low",
                PRIORITY_POLICY["low"]["quota_mb"],
                80.0,
                "unauthorized",
                PRIORITY_POLICY["low"]["qos_tag"],
            ),
        ]
        cur.executemany(
            """
            INSERT INTO devices (
                user_id, ip_address, mac_address, device_name, priority_level,
                total_quota_mb, used_quota_mb, status, qos_tag
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            seed_devices,
        )

    if cur.execute("SELECT COUNT(*) AS c FROM router_settings").fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO router_settings (id, wifi_name, wifi_password, security_type) VALUES (1, ?, ?, ?)",
            ("Smart_WiFi_Gateway", encrypt_secret("ChangeMeNow!"), "WPA3-Personal"),
        )
    else:
        # Re-encrypt legacy plaintext Wi-Fi passwords once
        row = cur.execute("SELECT wifi_password FROM router_settings WHERE id = 1").fetchone()
        if row and row["wifi_password"]:
            stored = row["wifi_password"]
            try:
                _fernet().decrypt(stored.encode("utf-8"))
            except (InvalidToken, ValueError, TypeError):
                cur.execute(
                    "UPDATE router_settings SET wifi_password = ? WHERE id = 1",
                    (encrypt_secret(stored),),
                )

    if cur.execute("SELECT COUNT(*) AS c FROM activity_logs").fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO activity_logs (message, created_at) VALUES (?, ?)",
            ("CoreRouter OS engine started — database initialized.", utc_now_str()),
        )

    # Backfill session expiry for legacy rows
    cur.execute(
        """
        UPDATE sessions
        SET expires_at = ?
        WHERE expires_at IS NULL OR expires_at = ''
        """,
        (session_expiry_str(),),
    )

    db.commit()
    db.close()


def add_log(message: str, db: sqlite3.Connection | None = None):
    conn = db or get_db()
    conn.execute(
        "INSERT INTO activity_logs (message, created_at) VALUES (?, ?)",
        (message, utc_now_str()),
    )
    if db is None:
        conn.commit()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def get_bearer_token():
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return request.headers.get("X-Auth-Token")


def current_user():
    token = get_bearer_token()
    if not token:
        return None
    db = get_db()
    cleanup_expired_sessions(db)
    db.commit()
    row = db.execute(
        """
        SELECT u.id, u.username, u.role, u.email, s.expires_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
        """,
        (token,),
    ).fetchone()
    if not row:
        return None
    expires = parse_utc(row["expires_at"])
    if expires and expires < utc_now():
        db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        db.commit()
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"], "email": row["email"]}


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify({"success": False, "message": "Authentication required"}), 401
        g.user = user
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if g.user["role"] != "admin":
            return jsonify({"success": False, "message": "Admin access required"}), 403
        return fn(*args, **kwargs)

    return wrapper


def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def check_login_rate_limit(ip: str) -> bool:
    """Return True if allowed, False if rate-limited."""
    now = time.time()
    with _login_lock:
        q = _login_attempts[ip]
        while q and now - q[0] > LOGIN_RATE_WINDOW_SEC:
            q.popleft()
        if len(q) >= LOGIN_RATE_LIMIT:
            return False
        q.append(now)
        return True


# ---------------------------------------------------------------------------
# Policy helpers
# ---------------------------------------------------------------------------
def compute_throttled(priority: str, used: float, total: float) -> bool:
    policy = PRIORITY_POLICY[priority]
    ratio = policy["throttle_at_ratio"]
    if ratio is None:
        return False
    if total <= 0:
        return True
    return (used / total) >= ratio


def apply_priority_to_device(
    device_id: int,
    priority: str,
    renew_quota: bool = True,
    *,
    db: sqlite3.Connection | None = None,
    commit: bool = True,
):
    policy = PRIORITY_POLICY[priority]
    conn = db or get_db()
    device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not device:
        return None

    used = 0.0 if renew_quota else float(device["used_quota_mb"])
    total = float(policy["quota_mb"])
    if used > total:
        used = total

    throttled = compute_throttled(priority, used, total)
    conn.execute(
        """
        UPDATE devices
        SET priority_level = ?, total_quota_mb = ?, used_quota_mb = ?,
            qos_tag = ?, throttled = ?
        WHERE id = ?
        """,
        (priority, total, used, policy["qos_tag"], 1 if throttled else 0, device_id),
    )
    if commit:
        conn.commit()
    return get_device(device_id, db=conn)


def enrich_device(row) -> dict:
    d = row_to_dict(row)
    if not d:
        return d
    total = float(d["total_quota_mb"] or 0)
    used = float(d["used_quota_mb"] or 0)
    remaining = max(total - used, 0)
    usage_ratio = (used / total) if total > 0 else 1.0
    priority = d["priority_level"]
    policy = PRIORITY_POLICY.get(priority, PRIORITY_POLICY["medium"])
    throttled = bool(d.get("throttled")) or compute_throttled(priority, used, total)

    alert = None
    if usage_ratio >= 1.0:
        alert = "quota_exhausted"
    elif usage_ratio >= 0.9:
        alert = "quota_critical"
    elif usage_ratio >= 0.75:
        alert = "quota_warning"

    d.update(
        {
            "remaining_quota_mb": round(remaining, 2),
            "usage_percent": round(usage_ratio * 100, 2),
            "throttled": throttled,
            "qos_tag": d.get("qos_tag") or policy["qos_tag"],
            "speed_cap_mbps": policy["speed_cap_mbps"],
            "allocation_policy": {
                "priority": priority,
                "quota_gb": policy["quota_mb"] / 1024,
                "qos_tag": policy["qos_tag"],
                "throttle_at_ratio": policy["throttle_at_ratio"],
                "auto_renew_on_admin_approval": policy["auto_renew_on_admin_approval"],
            },
            "quota_alert": alert,
        }
    )
    return d


def get_device(device_id: int, db: sqlite3.Connection | None = None):
    conn = db or get_db()
    row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    return enrich_device(row)


def list_devices(user_id=None, db: sqlite3.Connection | None = None):
    conn = db or get_db()
    if user_id is None:
        rows = conn.execute(
            """
            SELECT d.*, u.username AS owner_username
            FROM devices d
            LEFT JOIN users u ON u.id = d.user_id
            ORDER BY d.id
            """
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT d.*, u.username AS owner_username
            FROM devices d
            LEFT JOIN users u ON u.id = d.user_id
            WHERE d.user_id = ?
            ORDER BY d.id
            """,
            (user_id,),
        ).fetchall()
    return [enrich_device(r) for r in rows]


def safe_int(value, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


# ---------------------------------------------------------------------------
# Email (async)
# ---------------------------------------------------------------------------
def send_admin_notification(subject: str, body: str) -> bool:
    host = os.getenv("SMTP_HOST")
    port = safe_int(os.getenv("SMTP_PORT", "587"), 587)
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM", user or "")
    receiver = os.getenv("ADMIN_NOTIFY_EMAIL", "admin@example.com")

    if not all([host, user, password, sender]):
        log.info("SMTP not configured — notification logged only.\nSubject: %s\n%s", subject, body)
        return False

    message = MIMEMultipart()
    message["From"] = sender
    message["To"] = receiver
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(sender, receiver, message.as_string())
        log.info("Email sent: %s", subject)
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("Failed to send notification: %s", exc)
        return False


def enqueue_admin_notification(subject: str, body: str) -> None:
    thread = threading.Thread(
        target=send_admin_notification,
        args=(subject, body),
        daemon=True,
        name="smtp-notify",
    )
    thread.start()


def notify_priority_request(username, device, requested_priority, reason, duration_hours):
    dashboard = os.getenv("DASHBOARD_URL", ALLOWED_ORIGINS[0] if ALLOWED_ORIGINS else "http://127.0.0.1:3000")
    subject = f"[Alert] New Priority/Access Request: {username} ({device['device_name']})"
    body = f"""
A new network priority / access request requires review.

User Name          : {username}
Device Name        : {device['device_name']}
MAC Address        : {device['mac_address']}
IP Address         : {device['ip_address']}
Current Priority   : {device['priority_level']}
Requested Priority : {requested_priority}
Duration (hours)   : {duration_hours or 'N/A'}
Reason             : {reason or '(none provided)'}
Timestamp          : {utc_now_str()}

Review and approve/reject this request in the Admin dashboard:
{dashboard}

— Smart WiFi Monitor
""".strip()
    enqueue_admin_notification(subject, body)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "service": "smart-wifi-monitor", "time": utc_now_str()})


@app.route("/api/login", methods=["POST"])
def login():
    ip = client_ip()
    if not check_login_rate_limit(ip):
        return jsonify({
            "success": False,
            "message": "Too many login attempts. Try again later.",
        }), 429

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = get_db()
    cleanup_expired_sessions(db)
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    # Constant-ish path: always hash-check against a dummy when user missing
    password_hash = user["password_hash"] if user else _DUMMY_PASSWORD_HASH
    valid = bool(user) and check_password_hash(password_hash, password)
    if not valid:
        db.commit()
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

    token = secrets.token_hex(32)
    expires_at = session_expiry_str()
    db.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, user["id"], utc_now_str(), expires_at),
    )
    add_log(f"User '{username}' ({user['role']}) signed in.", db=db)
    db.commit()

    return jsonify(
        {
            "success": True,
            "token": token,
            "expires_at": expires_at,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "email": user["email"],
            },
        }
    )


@app.route("/api/logout", methods=["POST"])
@login_required
def logout():
    token = get_bearer_token()
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token = ?", (token,))
    db.commit()
    return jsonify({"success": True, "message": "Logged out"})


@app.route("/api/me", methods=["GET"])
@login_required
def me():
    return jsonify({"success": True, "user": g.user})


@app.route("/api/policy", methods=["GET"])
@login_required
def get_policy():
    global _POLICY_PAYLOAD_CACHE
    if _POLICY_PAYLOAD_CACHE is None:
        payload = {}
        for key, policy in PRIORITY_POLICY.items():
            payload[key] = {
                "quota_gb": policy["quota_mb"] / 1024,
                "quota_mb": policy["quota_mb"],
                "qos_tag": policy["qos_tag"],
                "throttle_at_ratio": policy["throttle_at_ratio"],
                "speed_cap_mbps": policy["speed_cap_mbps"],
                "auto_renew_on_admin_approval": policy["auto_renew_on_admin_approval"],
            }
        _POLICY_PAYLOAD_CACHE = payload
    return jsonify({"success": True, "policy": _POLICY_PAYLOAD_CACHE})


# ---------------------------------------------------------------------------
# Device routes
# ---------------------------------------------------------------------------
@app.route("/api/devices", methods=["GET"])
@login_required
def get_devices():
    if g.user["role"] == "admin":
        devices = list_devices()
    else:
        devices = list_devices(user_id=g.user["id"])
    return jsonify({"success": True, "devices": devices})


@app.route("/api/devices", methods=["POST"])
@admin_required
def add_device():
    data = request.get_json(silent=True) or {}
    name = (data.get("device_name") or data.get("name") or "").strip()
    ip = (data.get("ip_address") or data.get("ip") or "").strip()
    mac = (data.get("mac_address") or data.get("mac") or "").strip().upper()
    priority = (data.get("priority_level") or "medium").lower()
    status = (data.get("status") or "trusted").lower()
    user_id = data.get("user_id")

    if not name or not mac:
        return jsonify({"success": False, "message": "device_name and mac_address are required"}), 400
    if not MAC_RE.match(mac):
        return jsonify({"success": False, "message": "Invalid MAC address format"}), 400
    if ip and not IPV4_RE.match(ip):
        return jsonify({"success": False, "message": "Invalid IPv4 address"}), 400
    if priority not in VALID_PRIORITIES:
        return jsonify({"success": False, "message": "Invalid priority_level"}), 400
    if status not in VALID_DEVICE_STATUSES:
        return jsonify({"success": False, "message": "Invalid status"}), 400

    policy = PRIORITY_POLICY[priority]
    db = get_db()
    try:
        cur = db.execute(
            """
            INSERT INTO devices (
                user_id, ip_address, mac_address, device_name, priority_level,
                total_quota_mb, used_quota_mb, status, qos_tag, throttled
            ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, 0)
            """,
            (
                user_id,
                ip,
                mac,
                name,
                priority,
                policy["quota_mb"],
                status,
                policy["qos_tag"],
            ),
        )
        add_log(f"Device added: {name} [{mac}] status={status} priority={priority}", db=db)
        db.commit()
        return jsonify({"success": True, "device": get_device(cur.lastrowid)}), 201
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify({"success": False, "message": "Device MAC exists or invalid user_id"}), 409


@app.route("/api/devices/<int:device_id>", methods=["PATCH"])
@admin_required
def update_device(device_id):
    data = request.get_json(silent=True) or {}
    device = get_device(device_id)
    if not device:
        return jsonify({"success": False, "message": "Device not found"}), 404

    db = get_db()
    fields = []
    values = []

    if "status" in data:
        status = str(data["status"]).lower()
        if status not in VALID_DEVICE_STATUSES:
            return jsonify({"success": False, "message": "Invalid status"}), 400
        fields.append("status = ?")
        values.append(status)

    if "device_name" in data:
        fields.append("device_name = ?")
        values.append(str(data["device_name"]).strip())

    if "ip_address" in data:
        ip = str(data["ip_address"]).strip()
        if ip and not IPV4_RE.match(ip):
            return jsonify({"success": False, "message": "Invalid IPv4 address"}), 400
        fields.append("ip_address = ?")
        values.append(ip)

    if "user_id" in data:
        fields.append("user_id = ?")
        values.append(data["user_id"])

    if "used_quota_mb" in data:
        try:
            used = float(data["used_quota_mb"])
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": "used_quota_mb must be a number"}), 400
        used = max(0.0, min(used, float(device["total_quota_mb"])))
        fields.append("used_quota_mb = ?")
        values.append(used)
        throttled = compute_throttled(device["priority_level"], used, device["total_quota_mb"])
        fields.append("throttled = ?")
        values.append(1 if throttled else 0)

    try:
        if fields:
            values.append(device_id)
            db.execute(f"UPDATE devices SET {', '.join(fields)} WHERE id = ?", values)
            add_log(f"Device #{device_id} updated by admin.", db=db)

        if "priority_level" in data:
            priority = str(data["priority_level"]).lower()
            if priority not in VALID_PRIORITIES:
                db.rollback()
                return jsonify({"success": False, "message": "Invalid priority_level"}), 400
            # Default: keep the device's current usage (don't reset to 0) when the
            # priority tier changes. Pass renew_quota=true explicitly to reset it.
            renew = bool(data.get("renew_quota", False))
            apply_priority_to_device(device_id, priority, renew_quota=renew, db=db, commit=False)
            add_log(
                f"Device #{device_id} priority set to {priority}"
                + (" (quota reset)" if renew else " (usage kept)")
                + ".",
                db=db,
            )

        # Custom per-device quota (GB), selectable independently of the priority tier.
        # Applied last so it wins over any tier default set above, and it always keeps
        # the usage already accumulated (capped to the new total) instead of zeroing it.
        if "quota_gb" in data:
            try:
                quota_gb = float(data["quota_gb"])
            except (TypeError, ValueError):
                db.rollback()
                return jsonify({"success": False, "message": "quota_gb must be a number"}), 400
            if quota_gb not in VALID_QUOTA_GB:
                db.rollback()
                return jsonify({
                    "success": False,
                    "message": f"quota_gb must be one of {sorted(VALID_QUOTA_GB)}",
                }), 400

            current = db.execute(
                "SELECT used_quota_mb, priority_level FROM devices WHERE id = ?", (device_id,)
            ).fetchone()
            if current is None:
                db.rollback()
                return jsonify({"success": False, "message": "Device not found"}), 404

            new_total = quota_gb * 1024
            used = min(float(current["used_quota_mb"]), new_total)  # keep usage; only cap if it now exceeds the new total
            throttled = compute_throttled(current["priority_level"], used, new_total)
            db.execute(
                "UPDATE devices SET total_quota_mb = ?, used_quota_mb = ?, throttled = ? WHERE id = ?",
                (new_total, used, 1 if throttled else 0, device_id),
            )
            add_log(
                f"Device #{device_id} quota set to {quota_gb:g} GB by admin (usage kept at "
                f"{used:.1f} MB).",
                db=db,
            )

        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify({"success": False, "message": "Invalid update (constraint failed)"}), 409

    return jsonify({"success": True, "device": get_device(device_id)})


@app.route("/api/devices/<int:device_id>", methods=["DELETE"])
@admin_required
def remove_device(device_id):
    db = get_db()
    device = db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not device:
        return jsonify({"success": False, "message": "Device not found"}), 404
    db.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    add_log(
        f"Device blocked/removed: {device['device_name']} [{device['mac_address']}]",
        db=db,
    )
    db.commit()
    return jsonify({"success": True, "message": "Device removed"})


@app.route("/api/devices/<int:device_id>/usage", methods=["POST"])
@admin_required
def update_usage(device_id):
    data = request.get_json(silent=True) or {}
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        device = db.execute(
            "SELECT * FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        if not device:
            db.rollback()
            return jsonify({"success": False, "message": "Device not found"}), 404

        total = float(device["total_quota_mb"])
        if "used_quota_mb" in data:
            try:
                used = float(data["used_quota_mb"])
            except (TypeError, ValueError):
                db.rollback()
                return jsonify({"success": False, "message": "used_quota_mb must be a number"}), 400
        else:
            try:
                delta = float(data.get("delta_mb", 0))
            except (TypeError, ValueError):
                db.rollback()
                return jsonify({"success": False, "message": "delta_mb must be a number"}), 400
            used = float(device["used_quota_mb"]) + delta

        used = max(0.0, min(used, total))
        throttled = compute_throttled(device["priority_level"], used, total)
        db.execute(
            "UPDATE devices SET used_quota_mb = ?, throttled = ? WHERE id = ?",
            (used, 1 if throttled else 0, device_id),
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    updated = get_device(device_id)
    if updated.get("quota_alert") == "quota_critical":
        add_log(f"Quota critical (≥90%): {updated['device_name']}")
    elif updated.get("quota_alert") == "quota_exhausted":
        add_log(f"Quota exhausted: {updated['device_name']}")

    return jsonify({"success": True, "device": updated})


@app.route("/api/monitor/tick", methods=["POST"])
@admin_required
def monitor_tick():
    """Atomic server-side usage tick for trusted devices."""
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        rows = db.execute(
            "SELECT id, priority_level, total_quota_mb, used_quota_mb FROM devices WHERE status = 'trusted'"
        ).fetchall()
        updated_ids = []
        for row in rows:
            priority = row["priority_level"]
            rate = PRIORITY_POLICY[priority]["usage_rate_mb_per_tick"]
            # Atomic increment capped at total_quota_mb
            db.execute(
                """
                UPDATE devices
                SET used_quota_mb = MIN(used_quota_mb + ?, total_quota_mb)
                WHERE id = ?
                """,
                (rate, row["id"]),
            )
            refreshed = db.execute(
                "SELECT used_quota_mb, total_quota_mb, priority_level FROM devices WHERE id = ?",
                (row["id"],),
            ).fetchone()
            throttled = compute_throttled(
                refreshed["priority_level"],
                float(refreshed["used_quota_mb"]),
                float(refreshed["total_quota_mb"]),
            )
            db.execute(
                "UPDATE devices SET throttled = ? WHERE id = ?",
                (1 if throttled else 0, row["id"]),
            )
            updated_ids.append(row["id"])
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    return jsonify(
        {
            "success": True,
            "updated_count": len(updated_ids),
            "devices": list_devices(),
        }
    )


@app.route("/api/users", methods=["GET"])
@admin_required
def list_users():
    rows = get_db().execute(
        "SELECT id, username, role, email FROM users ORDER BY id"
    ).fetchall()
    return jsonify({"success": True, "users": [row_to_dict(r) for r in rows]})


# ---------------------------------------------------------------------------
# Priority requests
# ---------------------------------------------------------------------------
@app.route("/api/priority-requests", methods=["GET"])
@login_required
def get_priority_requests():
    db = get_db()
    if g.user["role"] == "admin":
        rows = db.execute(
            """
            SELECT pr.*, u.username, d.device_name, d.mac_address, d.ip_address,
                   d.priority_level AS current_priority
            FROM priority_requests pr
            JOIN users u ON u.id = pr.user_id
            JOIN devices d ON d.id = pr.device_id
            ORDER BY
                CASE pr.status WHEN 'pending' THEN 0 ELSE 1 END,
                pr.id DESC
            """
        ).fetchall()
    else:
        rows = db.execute(
            """
            SELECT pr.*, u.username, d.device_name, d.mac_address, d.ip_address,
                   d.priority_level AS current_priority
            FROM priority_requests pr
            JOIN users u ON u.id = pr.user_id
            JOIN devices d ON d.id = pr.device_id
            WHERE pr.user_id = ?
            ORDER BY pr.id DESC
            """,
            (g.user["id"],),
        ).fetchall()
    return jsonify({"success": True, "requests": [row_to_dict(r) for r in rows]})


@app.route("/api/priority-requests", methods=["POST"])
@login_required
def create_priority_request():
    data = request.get_json(silent=True) or {}
    device_id = data.get("device_id")
    requested = (data.get("requested_priority") or "high").lower()
    reason = (data.get("reason") or "").strip()
    duration_hours = data.get("duration_hours")

    if requested not in VALID_PRIORITIES:
        return jsonify({"success": False, "message": "Invalid requested_priority"}), 400
    if not device_id:
        return jsonify({"success": False, "message": "device_id is required"}), 400

    db = get_db()
    device_row = db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not device_row:
        return jsonify({"success": False, "message": "Device not found"}), 404

    if g.user["role"] != "admin" and device_row["user_id"] != g.user["id"]:
        return jsonify({"success": False, "message": "Not your device"}), 403

    if not reason:
        return jsonify({"success": False, "message": "A justification/reason is required"}), 400

    if duration_hours is not None:
        duration_hours = safe_int(duration_hours, -1, minimum=1, maximum=720)
        if duration_hours < 1:
            return jsonify({"success": False, "message": "duration_hours must be 1–720"}), 400

    pending = db.execute(
        """
        SELECT id FROM priority_requests
        WHERE device_id = ? AND user_id = ? AND status = 'pending'
        """,
        (
            device_id,
            g.user["id"] if g.user["role"] != "admin" else (device_row["user_id"] or g.user["id"]),
        ),
    ).fetchone()
    if pending:
        return jsonify({
            "success": False,
            "message": "A pending request already exists for this device",
        }), 409

    cur = db.execute(
        """
        INSERT INTO priority_requests (
            user_id, device_id, requested_priority, reason, duration_hours, status, created_at
        ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            g.user["id"] if g.user["role"] != "admin" else (device_row["user_id"] or g.user["id"]),
            device_id,
            requested,
            reason,
            duration_hours,
            utc_now_str(),
        ),
    )
    request_id = cur.lastrowid
    device = enrich_device(device_row)
    add_log(
        f"Priority request #{request_id}: {g.user['username']} asked {requested} "
        f"for {device['device_name']}",
        db=db,
    )
    db.commit()

    notify_priority_request(
        g.user["username"], device, requested, reason, duration_hours
    )

    row = db.execute(
        """
        SELECT pr.*, u.username, d.device_name, d.mac_address, d.ip_address,
               d.priority_level AS current_priority
        FROM priority_requests pr
        JOIN users u ON u.id = pr.user_id
        JOIN devices d ON d.id = pr.device_id
        WHERE pr.id = ?
        """,
        (request_id,),
    ).fetchone()

    return jsonify({"success": True, "request": row_to_dict(row)}), 201


@app.route("/api/priority-requests/<int:request_id>/approve", methods=["POST"])
@admin_required
def approve_request(request_id):
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        cur = db.execute(
            """
            UPDATE priority_requests
            SET status = 'approved', reviewed_at = ?
            WHERE id = ? AND status = 'pending'
            """,
            (utc_now_str(), request_id),
        )
        if cur.rowcount == 0:
            existing = db.execute(
                "SELECT status FROM priority_requests WHERE id = ?", (request_id,)
            ).fetchone()
            db.rollback()
            if not existing:
                return jsonify({"success": False, "message": "Request not found"}), 404
            return jsonify({
                "success": False,
                "message": f"Request already {existing['status']}",
            }), 409

        req = db.execute(
            "SELECT * FROM priority_requests WHERE id = ?", (request_id,)
        ).fetchone()
        priority = req["requested_priority"]
        renew = PRIORITY_POLICY[priority]["auto_renew_on_admin_approval"]
        device = apply_priority_to_device(
            req["device_id"], priority, renew_quota=renew, db=db, commit=False
        )
        db.execute(
            "UPDATE devices SET status = 'trusted' WHERE id = ?",
            (req["device_id"],),
        )
        add_log(
            f"Request #{request_id} APPROVED — {device['device_name']} → {priority}"
            + (" (quota renewed)" if renew else ""),
            db=db,
        )
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    return jsonify(
        {
            "success": True,
            "message": "Request approved",
            "device": get_device(req["device_id"]),
        }
    )


@app.route("/api/priority-requests/<int:request_id>/reject", methods=["POST"])
@admin_required
def reject_request(request_id):
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        cur = db.execute(
            """
            UPDATE priority_requests
            SET status = 'rejected', reviewed_at = ?
            WHERE id = ? AND status = 'pending'
            """,
            (utc_now_str(), request_id),
        )
        if cur.rowcount == 0:
            existing = db.execute(
                "SELECT status FROM priority_requests WHERE id = ?", (request_id,)
            ).fetchone()
            db.rollback()
            if not existing:
                return jsonify({"success": False, "message": "Request not found"}), 404
            return jsonify({
                "success": False,
                "message": f"Request already {existing['status']}",
            }), 409

        add_log(f"Request #{request_id} REJECTED by admin.", db=db)
        db.commit()
    except sqlite3.Error:
        db.rollback()
        raise

    return jsonify({"success": True, "message": "Request rejected"})


# ---------------------------------------------------------------------------
# Router settings & logs
# ---------------------------------------------------------------------------
@app.route("/api/router/settings", methods=["GET"])
@admin_required
def get_router_settings():
    now = time.time()
    with _CACHE_LOCK:
        if (
            _ROUTER_CACHE["data"] is not None
            and now - float(_ROUTER_CACHE["ts"]) < _ROUTER_CACHE_TTL_SEC
        ):
            return jsonify({"success": True, "settings": _ROUTER_CACHE["data"]})

    row = get_db().execute("SELECT * FROM router_settings WHERE id = 1").fetchone()
    data = row_to_dict(row) or {}
    raw_sec = data.get("security_type") or "WPA3-Personal"
    data["security_type"] = SECURITY_TYPE_ALIASES.get(raw_sec, raw_sec)
    if data.get("wifi_password"):
        data["wifi_password_set"] = True
        data["wifi_password"] = "********"
    else:
        data["wifi_password_set"] = False
        data["wifi_password"] = "********"

    with _CACHE_LOCK:
        _ROUTER_CACHE["data"] = data
        _ROUTER_CACHE["ts"] = now
    return jsonify({"success": True, "settings": data})


@app.route("/api/router/settings", methods=["POST", "PUT"])
@admin_required
def update_router_settings():
    data = request.get_json(silent=True) or {}
    wifi_name = (data.get("wifiName") or data.get("wifi_name") or "").strip()
    wifi_password = data.get("wifiPassword") or data.get("wifi_password")
    security_type = (
        data.get("securityType") or data.get("security_type") or "WPA3-Personal"
    ).strip()
    security_type = SECURITY_TYPE_ALIASES.get(security_type, security_type)

    if not wifi_name:
        return jsonify({"success": False, "message": "Network name (SSID) is required"}), 400
    if len(wifi_name) > 32:
        return jsonify({"success": False, "message": "SSID must be 32 characters or fewer"}), 400
    if security_type not in {"WPA2-PSK", "WPA3-Personal"}:
        return jsonify({
            "success": False,
            "message": "security_type must be WPA2-PSK or WPA3-Personal",
        }), 400

    db = get_db()
    existing = db.execute("SELECT * FROM router_settings WHERE id = 1").fetchone()
    if wifi_password in (None, "", "********"):
        encrypted = existing["wifi_password"] if existing else ""
    else:
        plain = str(wifi_password)
        if len(plain) < 8:
            return jsonify({
                "success": False,
                "message": "Wi-Fi password must be at least 8 characters",
            }), 400
        encrypted = encrypt_secret(plain)

    db.execute(
        """
        INSERT INTO router_settings (id, wifi_name, wifi_password, security_type)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            wifi_name = excluded.wifi_name,
            wifi_password = excluded.wifi_password,
            security_type = excluded.security_type
        """,
        (wifi_name, encrypted, security_type),
    )
    add_log(
        f"Router settings updated — SSID: {wifi_name}, security: {security_type}",
        db=db,
    )
    db.commit()
    with _CACHE_LOCK:
        _ROUTER_CACHE["data"] = None
        _ROUTER_CACHE["ts"] = 0.0
    log.info("Router settings updated SSID=%s security=%s", wifi_name, security_type)

    return jsonify(
        {
            "success": True,
            "message": "Wi-Fi settings updated successfully",
            "settings": {
                "wifi_name": wifi_name,
                "security_type": security_type,
                "wifi_password": "********",
                "wifi_password_set": bool(encrypted),
            },
        }
    )


@app.route("/api/logs", methods=["GET"])
@login_required
def get_logs():
    limit = safe_int(request.args.get("limit", 30), 30, minimum=1, maximum=100)
    # Clients only see their own activity-adjacent messages is Phase-2; for now
    # restrict full operational logs to admins.
    if g.user["role"] != "admin":
        return jsonify({"success": True, "logs": []})

    rows = get_db().execute(
        "SELECT * FROM activity_logs ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return jsonify({"success": True, "logs": [row_to_dict(r) for r in rows]})


@app.route("/api/reports/devices.csv", methods=["GET"])
@admin_required
def export_devices_csv():
    """Admin CSV export of device inventory, quotas, and alert status."""
    devices = list_devices()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "device_id",
            "device_name",
            "owner",
            "ip_address",
            "mac_address",
            "priority",
            "status",
            "qos_tag",
            "total_quota_gb",
            "used_quota_gb",
            "remaining_quota_gb",
            "usage_percent",
            "throttled",
            "quota_alert",
            "exported_at",
        ]
    )
    exported_at = utc_now_str()
    for d in devices:
        writer.writerow(
            [
                d.get("id"),
                d.get("device_name"),
                d.get("owner_username") or "",
                d.get("ip_address") or "",
                d.get("mac_address") or "",
                d.get("priority_level") or "",
                d.get("status") or "",
                d.get("qos_tag") or "",
                round(float(d.get("total_quota_mb") or 0) / 1024, 3),
                round(float(d.get("used_quota_mb") or 0) / 1024, 3),
                round(float(d.get("remaining_quota_mb") or 0) / 1024, 3),
                d.get("usage_percent"),
                "yes" if d.get("throttled") else "no",
                d.get("quota_alert") or "",
                exported_at,
            ]
        )

    add_log(f"Admin '{g.user['username']}' exported devices CSV ({len(devices)} rows).")
    stamp = utc_now().strftime("%Y%m%d-%H%M%S")
    filename = f"smart-wifi-devices-{stamp}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


# ---------------------------------------------------------------------------
# NEW: Packet handling + enforcing proxy (see packet_handler.py / proxy_server.py)
# Use ONE of them (or neither). Running both counts usage twice.
# ---------------------------------------------------------------------------
def _packet_db() -> sqlite3.Connection:
    """Fresh, configured SQLite connection for background threads."""
    return configure_connection(sqlite3.connect(DATABASE, timeout=30.0))


packet_monitor = PacketMonitor(
    db_factory=_packet_db,
    compute_throttled=compute_throttled,
    add_log=add_log,
    policy=PRIORITY_POLICY,
)
register_packet_routes(app, packet_monitor, admin_required)

proxy_server = ProxyServer(
    db_factory=_packet_db,
    compute_throttled=compute_throttled,
    add_log=add_log,
    policy=PRIORITY_POLICY,
)
register_proxy_routes(app, proxy_server, admin_required)

# NEW: live traffic (per-device flow, connected devices) for the admin dashboard
register_traffic_routes(app, proxy_server, admin_required, list_devices)

# NEW: device self-registration portal (/portal), /api/devices/register-self, /proxy.pac
register_self_service_routes(
    app,
    get_db=get_db,
    login_required=login_required,
    add_log=add_log,
    get_device=get_device,
    policy=PRIORITY_POLICY,
    compute_throttled=compute_throttled,
)


def _env_flag(name: str) -> bool:
    return (os.getenv(name, "0") or "0").strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
init_db()

# NEW: optional auto-start (set in .env)
if _env_flag("PACKET_CAPTURE_ENABLED"):
    log.info("Packet capture: %s", packet_monitor.start()[1])
if _env_flag("PROXY_ENABLED"):
    log.info("Proxy: %s", proxy_server.start()[1])


if __name__ == "__main__":
    # Always bind loopback:5000 for local React integration unless overridden.
    debug = os.getenv("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}
    host = os.getenv("FLASK_HOST", "127.0.0.1") or "127.0.0.1"
    port = safe_int(os.getenv("FLASK_PORT", "5000"), 5000, minimum=1, maximum=65535)
    if host == "0.0.0.0" and debug:
        log.warning("Refusing debug=True with host=0.0.0.0 — forcing debug=False")
        debug = False

    banner = f"""
============================================================
  Smart WiFi Monitor API
  Backend running at http://{host}:{port}
  Health check:      http://{host}:{port}/api/health
  CORS origins:      {', '.join(ALLOWED_ORIGINS)}
  Demo logins:       admin / Admin@123  |  client / Client@123
============================================================
"""
    print(banner, flush=True)
    log.info("Starting Smart WiFi Monitor on %s:%s (debug=%s)", host, port, debug)
    app.run(debug=debug, host=host, port=port, use_reloader=False)
