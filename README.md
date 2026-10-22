# Smart WiFi Monitor

Integrated **React + Flask + SQLite** network control center (“CoreRouter OS”) with role-based access, a deterministic priority/quota policy engine, client priority requests, and admin email notifications.

## Architecture

```
frontend/ (React, port 3000)
    │  Bearer token + JSON
    ▼
backend/app.py (Flask, port 5000)
    ├── Auth sessions (admin | user)
    ├── devices + priority_requests + router_settings
    ├── Policy engine (High / Medium / Low quotas & throttle rules)
    └── SMTP alerts (optional via .env)
         └── SQLite: network_monitor.db
```

| Role | Capabilities |
|------|----------------|
| **Admin** | Full device inventory, live usage ticks, approve/reject requests, router settings, block devices |
| **User / Client** | View owned devices & quotas, submit priority/access requests |

### Priority & quota policy

| Priority | Quota / cycle | Allocation policy |
|----------|---------------|-------------------|
| **High** | 50 GB | Unthrottled; QoS `Voice/Video/Mission-Critical`; quota auto-renews on admin approval |
| **Medium** | 20 GB | Standard bandwidth; throttled after **90%** consumption |
| **Low** (guests / IoT) | 5 GB | Capped speeds; treated as congested/capped tier |

## Prerequisites

- Python 3.10+
- Node.js 18+ and npm

## Quick start (Windows)

Double-click **`run_all.bat`** for an instant launch:

- Skips `pip install` / `npm install` when `.venv` and `node_modules` already exist
- Starts Flask + React **in parallel** (no artificial wait)
- Pass **`run_all.bat --install`** only when dependencies changed

Then open **http://127.0.0.1:3000**.

### Manual start

```bash
# Terminal 1 — API
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python app.py

# Terminal 2 — UI
cd frontend
npm install
npm start
```

Then open **http://127.0.0.1:3000** (or http://localhost:3000).

### Key API routes

| Method | Path | Notes |
|--------|------|--------|
| POST | `/api/login` | Returns Bearer token |
| GET | `/api/devices` | Admin: all; user: owned only |
| POST | `/api/devices` | Admin: register device |
| PATCH | `/api/devices/<id>` | Admin: status / priority / ownership |
| POST | `/api/monitor/tick` | Admin: server-side usage increment |
| GET/POST | `/api/priority-requests` | List / create |
| POST | `/api/priority-requests/<id>/approve` | Admin |
| POST | `/api/priority-requests/<id>/reject` | Admin |
| GET | `/api/reports/devices.csv` | Admin CSV export (usage / quotas / alerts) |
| GET/POST | `/api/router/settings` | Admin wireless settings |

If SMTP is not configured, request alerts are **logged** and the API still succeeds (mail runs in a background thread).

### Phase 1 hardening defaults

| Setting | Default | Purpose |
|---------|---------|---------|
| `FLASK_DEBUG` | `0` | Debugger off |
| `FLASK_HOST` | `127.0.0.1` | No `0.0.0.0` bind by default |
| `FRONTEND_ORIGIN` | `http://localhost:3000` | CORS allowlist (not `*`) |
| `SESSION_TTL_HOURS` | `8` | Bearer token expiry + cleanup |
| `LOGIN_RATE_LIMIT` | `10` / 300s | Brute-force protection |
| Wi‑Fi password | Fernet-encrypted at rest | Derived from `FLASK_SECRET_KEY` or `FERNET_KEY` |

## Frontend setup

```bash
cd frontend
npm install
npm start
```

App opens at **http://localhost:3000** and calls the Flask API at `http://localhost:5000` (override with `REACT_APP_API_URL` if needed).

## Default demo credentials

| Account | Username | Password | Role |
|---------|----------|----------|------|
| Network Admin | `admin` | `Admin@123` | admin |
| Client | `client` | `Client@123` | user |
| Guest | `guest` | `Guest@123` | user |

Seeded devices are assigned to `client` and `guest`, plus one unauthorized intruder for the admin view.

## Typical demo flow

1. Start backend, then frontend.
2. Sign in as **client** → open **Request priority / access** → submit a High Priority request with a reason.
3. Sign out; sign in as **admin** → approve the request (High priority renews quota) or reject it.
4. Optionally enable **Live usage tick** on the admin dashboard to accumulate server-side usage and observe throttle thresholds.

## Project layout

```
smart-wifi-monitor/
├── README.md
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   ├── .env.example
│   └── network_monitor.db   # created on first run
└── frontend/
    ├── package.json
    └── src/
        ├── api.js
        ├── App.js
        └── components/
            ├── Login.js
            ├── Dashboard.js      # AdminDashboard + ClientPortal
            ├── Settings.js
            └── PriorityRequestModal.js
```

## Notes

- This project models **policy and control workflows**. It does not sniff live Wi‑Fi frames or reconfigure a physical router appliance.
- Delete `backend/network_monitor.db` to reset seed data and recreate tables on next start.
- Prefer a new `.venv` under `backend/`; older virtualenvs copied from another machine may point at invalid Python paths.
