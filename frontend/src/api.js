const API_BASE = (
  process.env.REACT_APP_API_URL || "http://127.0.0.1:5000"
).replace(/\/$/, "");

const BACKEND_DOWN_MSG =
  "Cannot connect to backend server. Please verify Flask is running on port 5000.";

function authHeaders() {
  const token = localStorage.getItem("swm_token");
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function normalizePath(path) {
  if (!path) return "/api";
  if (path.startsWith("/api")) return path;
  return `/api${path.startsWith("/") ? path : `/${path}`}`;
}

async function request(path, options = {}) {
  const { signal, ...rest } = options;
  const url = `${API_BASE}${normalizePath(path)}`;
  let res;
  try {
    res = await fetch(url, {
      ...rest,
      signal,
      headers: {
        ...authHeaders(),
        ...(rest.headers || {}),
      },
    });
  } catch (networkErr) {
    if (networkErr?.name === "AbortError") {
      const abortErr = new Error("Request aborted");
      abortErr.status = 0;
      abortErr.code = "ABORTED";
      abortErr.cause = networkErr;
      throw abortErr;
    }
    const error = new Error(BACKEND_DOWN_MSG);
    error.status = 0;
    error.code = "BACKEND_UNREACHABLE";
    error.cause = networkErr;
    throw error;
  }

  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }

  if (!res.ok) {
    const message = (data && data.message) || `Request failed (${res.status})`;
    const error = new Error(message);
    error.status = res.status;
    error.data = data;
    throw error;
  }
  return data;
}

export const api = {
  baseUrl: API_BASE,
  backendDownMessage: BACKEND_DOWN_MSG,
  health: (opts) => request("/api/health", opts),
  login: (username, password, opts) =>
    request("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
      ...opts,
    }),
  logout: (opts) => request("/api/logout", { method: "POST", ...opts }),
  me: (opts) => request("/api/me", opts),
  policy: (opts) => request("/api/policy", opts),
  getDevices: (opts) => request("/api/devices", opts),
  addDevice: (payload, opts) =>
    request("/api/devices", {
      method: "POST",
      body: JSON.stringify(payload),
      ...opts,
    }),
  updateDevice: (id, payload, opts) =>
    request(`/api/devices/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
      ...opts,
    }),
  removeDevice: (id, opts) =>
    request(`/api/devices/${id}`, { method: "DELETE", ...opts }),
  updateUsage: (id, payload, opts) =>
    request(`/api/devices/${id}/usage`, {
      method: "POST",
      body: JSON.stringify(payload),
      ...opts,
    }),
  monitorTick: (opts) =>
    request("/api/monitor/tick", { method: "POST", ...opts }),
  getUsers: (opts) => request("/api/users", opts),
  getRequests: (opts) => request("/api/priority-requests", opts),
  createRequest: (payload, opts) =>
    request("/api/priority-requests", {
      method: "POST",
      body: JSON.stringify(payload),
      ...opts,
    }),
  approveRequest: (id, opts) =>
    request(`/api/priority-requests/${id}/approve`, {
      method: "POST",
      ...opts,
    }),
  rejectRequest: (id, opts) =>
    request(`/api/priority-requests/${id}/reject`, {
      method: "POST",
      ...opts,
    }),
  getRouterSettings: (opts) => request("/api/router/settings", opts),
  updateRouterSettings: (payload, opts) =>
    request("/api/router/settings", {
      method: "POST",
      body: JSON.stringify(payload),
      ...opts,
    }),
  getLogs: (limit = 30, opts) =>
    request(`/api/logs?limit=${limit}`, opts),
  downloadDevicesCsv: async (opts = {}) => {
    const url = `${API_BASE}/api/reports/devices.csv`;
    let res;
    try {
      res = await fetch(url, { headers: authHeaders(), signal: opts.signal });
    } catch (networkErr) {
      if (networkErr?.name === "AbortError") {
        const abortErr = new Error("Request aborted");
        abortErr.code = "ABORTED";
        throw abortErr;
      }
      const error = new Error(BACKEND_DOWN_MSG);
      error.status = 0;
      error.code = "BACKEND_UNREACHABLE";
      error.cause = networkErr;
      throw error;
    }
    if (!res.ok) {
      let message = `Export failed (${res.status})`;
      try {
        const data = await res.json();
        if (data?.message) message = data.message;
      } catch {
        /* ignore */
      }
      const error = new Error(message);
      error.status = res.status;
      throw error;
    }
    const blob = await res.blob();
    const disposition = res.headers.get("Content-Disposition") || "";
    const match = /filename="?([^";]+)"?/i.exec(disposition);
    const filename = match?.[1] || `smart-wifi-devices-${Date.now()}.csv`;
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
    return { filename };
  },
};

export function formatGb(mb) {
  if (mb == null || Number.isNaN(Number(mb))) return "—";
  return `${(Number(mb) / 1024).toFixed(2)} GB`;
}

export function priorityLabel(level) {
  if (!level) return "—";
  return level.charAt(0).toUpperCase() + level.slice(1);
}

export default api;
