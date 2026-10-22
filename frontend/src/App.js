import React, { useCallback, useEffect, useRef, useState } from "react";
import Login from "./components/Login";
import Settings from "./components/Settings";
import { AdminDashboard, ClientPortal } from "./components/Dashboard";
import { api } from "./api";
import "./App.css";

const TOKEN_KEY = "swm_token";
const USER_KEY = "swm_user";

function App() {
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || "null");
    } catch {
      return null;
    }
  });
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY));
  const [view, setView] = useState("dashboard");
  const [devices, setDevices] = useState([]);
  const [requests, setRequests] = useState([]);
  const [logs, setLogs] = useState([]);
  const [users, setUsers] = useState([]);
  const [policy, setPolicy] = useState(null);
  const [liveMonitor, setLiveMonitor] = useState(true);
  const [message, setMessage] = useState("");
  const [messageTone, setMessageTone] = useState("info");
  const [loginError, setLoginError] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);
  const [booting, setBooting] = useState(Boolean(localStorage.getItem(TOKEN_KEY)));
  const [exporting, setExporting] = useState(false);

  const seenQuotaAlerts = useRef(new Set());
  const pendingCountRef = useRef(null);
  const alertsReady = useRef(false);

  const flash = useCallback((text, tone = "info") => {
    setMessage(text);
    setMessageTone(tone);
    window.clearTimeout(flash._t);
    flash._t = window.setTimeout(() => {
      setMessage("");
      setMessageTone("info");
    }, 4500);
  }, []);

  const clearSession = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setToken(null);
    setUser(null);
    setDevices([]);
    setRequests([]);
    setLogs([]);
    setUsers([]);
    setView("dashboard");
    seenQuotaAlerts.current = new Set();
    pendingCountRef.current = null;
    alertsReady.current = false;
  }, []);

  const refreshAll = useCallback(async () => {
    if (!token) return;
    try {
      const [devRes, reqRes, policyRes, logRes] = await Promise.all([
        api.getDevices(),
        api.getRequests(),
        api.policy(),
        api.getLogs(40),
      ]);
      setDevices(devRes.devices || []);
      setRequests(reqRes.requests || []);
      setPolicy(policyRes.policy || null);
      setLogs(logRes.logs || []);

      const me = JSON.parse(localStorage.getItem(USER_KEY) || "null");
      if (me?.role === "admin") {
        const usersRes = await api.getUsers();
        setUsers(usersRes.users || []);
      }
    } catch (err) {
      if (err.status === 401) {
        clearSession();
        setLoginError("Session expired. Please sign in again.");
      } else if (err.code === "BACKEND_UNREACHABLE" || err.status === 0) {
        flash(api.backendDownMessage, "danger");
        setLoginError(api.backendDownMessage);
      } else {
        flash(err.message || "Failed to refresh data", "danger");
      }
    }
  }, [token, clearSession, flash]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!token) {
        setBooting(false);
        return;
      }
      try {
        const data = await api.me();
        if (cancelled) return;
        setUser(data.user);
        localStorage.setItem(USER_KEY, JSON.stringify(data.user));
        await refreshAll();
      } catch {
        if (!cancelled) clearSession();
      } finally {
        if (!cancelled) setBooting(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [token, refreshAll, clearSession]);

  // Live usage tick + request poll (admin dashboard only; pause when tab hidden)
  useEffect(() => {
    if (
      !token ||
      !user ||
      user.role !== "admin" ||
      !liveMonitor ||
      view !== "dashboard"
    ) {
      return undefined;
    }

    let cancelled = false;
    let controller = null;
    let tickCount = 0;

    const runTick = async () => {
      if (cancelled || document.visibilityState === "hidden") return;
      if (controller) controller.abort();
      controller = new AbortController();
      const { signal } = controller;
      try {
        const [tickRes, reqRes] = await Promise.all([
          api.monitorTick({ signal }),
          api.getRequests({ signal }),
        ]);
        if (cancelled || signal.aborted) return;
        setDevices(tickRes.devices || []);
        setRequests(reqRes.requests || []);
        tickCount += 1;
        // Fetch logs every other tick to cut chatter
        if (tickCount % 2 === 0) {
          const logRes = await api.getLogs(40, { signal });
          if (cancelled || signal.aborted) return;
          setLogs(logRes.logs || []);
        }
      } catch (err) {
        if (cancelled || err.code === "ABORTED") return;
        if (err.status === 401) clearSession();
        else flash(err.message || "Live monitor tick failed", "danger");
      }
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") runTick();
    };
    document.addEventListener("visibilitychange", onVisibility);
    const id = setInterval(runTick, 4000);
    runTick();

    return () => {
      cancelled = true;
      if (controller) controller.abort();
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [token, user, liveMonitor, view, clearSession, flash]);

  // Client poll — pause when hidden; abort overlapping requests
  useEffect(() => {
    if (!token || !user || user.role !== "user") return undefined;

    let cancelled = false;
    let controller = null;

    const runPoll = async () => {
      if (cancelled || document.visibilityState === "hidden") return;
      if (controller) controller.abort();
      controller = new AbortController();
      const { signal } = controller;
      try {
        const [devRes, reqRes] = await Promise.all([
          api.getDevices({ signal }),
          api.getRequests({ signal }),
        ]);
        if (cancelled || signal.aborted) return;
        setDevices(devRes.devices || []);
        setRequests(reqRes.requests || []);
      } catch (err) {
        if (cancelled || err.code === "ABORTED") return;
        if (err.status === 401) clearSession();
      }
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") runPoll();
    };
    document.addEventListener("visibilitychange", onVisibility);
    const id = setInterval(runPoll, 8000);
    runPoll();

    return () => {
      cancelled = true;
      if (controller) controller.abort();
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [token, user, clearSession]);

  // Toast alerts: quota thresholds + new pending requests
  useEffect(() => {
    if (!user) return;

    // Skip first paint after load to avoid toast spam on existing state
    if (!alertsReady.current) {
      devices.forEach((d) => {
        if (d.quota_alert) {
          seenQuotaAlerts.current.add(`${d.id}:${d.quota_alert}`);
        }
      });
      pendingCountRef.current = requests.filter((r) => r.status === "pending").length;
      alertsReady.current = true;
      return;
    }

    devices.forEach((d) => {
      if (!d.quota_alert) return;
      const key = `${d.id}:${d.quota_alert}`;
      if (seenQuotaAlerts.current.has(key)) return;
      seenQuotaAlerts.current.add(key);
      if (d.quota_alert === "quota_exhausted") {
        flash(`Quota exhausted: ${d.device_name}`, "danger");
      } else if (d.quota_alert === "quota_critical") {
        flash(`Quota critical (≥90%): ${d.device_name}`, "warning");
      } else if (d.quota_alert === "quota_warning") {
        flash(`Quota warning (≥75%): ${d.device_name}`, "warning");
      }
    });

    if (user.role === "admin") {
      const pending = requests.filter((r) => r.status === "pending").length;
      if (pendingCountRef.current != null && pending > pendingCountRef.current) {
        const added = pending - pendingCountRef.current;
        flash(
          `${added} new priority/access request${added > 1 ? "s" : ""} pending review`,
          "warning"
        );
      }
      pendingCountRef.current = pending;
    }
  }, [devices, requests, user, flash]);

  const handleLogin = async (username, password) => {
    setLoginLoading(true);
    setLoginError("");
    try {
      const data = await api.login(username, password);
      localStorage.setItem(TOKEN_KEY, data.token);
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
      seenQuotaAlerts.current = new Set();
      pendingCountRef.current = null;
      alertsReady.current = false;
      setToken(data.token);
      setUser(data.user);
      setView("dashboard");
      if (data.user?.role === "admin") {
        setLiveMonitor(true);
      }
    } catch (err) {
      const msg =
        err.code === "BACKEND_UNREACHABLE" || err.status === 0
          ? api.backendDownMessage
          : err.message || "Login failed";
      setLoginError(msg);
    } finally {
      setLoginLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch {
      /* ignore */
    }
    clearSession();
  };

  const handleExportCsv = useCallback(async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const result = await api.downloadDevicesCsv();
      flash(`CSV exported: ${result.filename}`, "success");
      await refreshAll();
    } catch (err) {
      if (err.code !== "ABORTED") {
        flash(err.message || "CSV export failed", "danger");
      }
    } finally {
      setExporting(false);
    }
  }, [exporting, flash, refreshAll]);

  const onAddDevice = useCallback(
    async (payload) => {
      try {
        await api.addDevice(payload);
        flash("Device added", "success");
        await refreshAll();
      } catch (err) {
        flash(err.message || "Failed to add device", "danger");
        throw err;
      }
    },
    [flash, refreshAll]
  );

  const onUpdateDevice = useCallback(
    async (id, payload) => {
      try {
        await api.updateDevice(id, payload);
        flash("Device updated", "success");
        await refreshAll();
      } catch (err) {
        flash(err.message || "Failed to update device", "danger");
      }
    },
    [flash, refreshAll]
  );

  const onRemoveDevice = useCallback(
    async (id) => {
      if (!window.confirm("Remove / block this device?")) return;
      try {
        await api.removeDevice(id);
        flash("Device removed", "success");
        await refreshAll();
      } catch (err) {
        flash(err.message || "Failed to remove device", "danger");
      }
    },
    [flash, refreshAll]
  );

  const onApprove = useCallback(
    async (id) => {
      try {
        await api.approveRequest(id);
        flash("Request approved", "success");
        await refreshAll();
      } catch (err) {
        flash(err.message || "Failed to approve request", "danger");
      }
    },
    [flash, refreshAll]
  );

  const onReject = useCallback(
    async (id) => {
      try {
        await api.rejectRequest(id);
        flash("Request rejected", "success");
        await refreshAll();
      } catch (err) {
        flash(err.message || "Failed to reject request", "danger");
      }
    },
    [flash, refreshAll]
  );

  const onCreateRequest = useCallback(
    async (payload) => {
      try {
        await api.createRequest(payload);
        flash("Request submitted — admin notified", "success");
        await refreshAll();
      } catch (err) {
        flash(err.message || "Failed to submit request", "danger");
        throw err;
      }
    },
    [flash, refreshAll]
  );

  const onSettingsMessage = useCallback(
    (msg, tone = "info") => flash(msg, tone),
    [flash]
  );

  if (booting) {
    return <div className="boot-screen">Loading Smart WiFi Monitor…</div>;
  }

  if (!user || !token) {
    return (
      <Login onLogin={handleLogin} error={loginError} loading={loginLoading} />
    );
  }

  const isAdmin = user.role === "admin";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">SW</div>
          <div>
            <h1>CoreRouter OS</h1>
            <p>v2.1 · {isAdmin ? "Network Admin" : "Client Portal"}</p>
          </div>
        </div>

        <nav className="nav">
          <button
            type="button"
            className={view === "dashboard" ? "active" : ""}
            onClick={() => setView("dashboard")}
          >
            {isAdmin ? "Bandwidth Monitor" : "My Devices"}
          </button>
          {isAdmin && (
            <button
              type="button"
              className={view === "settings" ? "active" : ""}
              onClick={() => setView("settings")}
            >
              Router Panel / Wi-Fi Settings
            </button>
          )}
        </nav>

        <div className="sidebar-foot">
          <div className="user-chip">
            <strong>{user.username}</strong>
            <span>{user.role}</span>
          </div>
          <button type="button" className="btn-logout" onClick={handleLogout}>
            Sign out
          </button>
        </div>
      </aside>

      <main className="main">
        {view === "settings" && isAdmin ? (
          <Settings onMessage={onSettingsMessage} />
        ) : isAdmin ? (
          <AdminDashboard
            user={user}
            devices={devices}
            requests={requests}
            logs={logs}
            policy={policy}
            users={users}
            liveMonitor={liveMonitor}
            setLiveMonitor={setLiveMonitor}
            message={message}
            messageTone={messageTone}
            onRefresh={refreshAll}
            onExportCsv={handleExportCsv}
            onAddDevice={onAddDevice}
            onUpdateDevice={onUpdateDevice}
            onRemoveDevice={onRemoveDevice}
            onApprove={onApprove}
            onReject={onReject}
          />
        ) : (
          <ClientPortal
            user={user}
            devices={devices}
            requests={requests}
            policy={policy}
            message={message}
            messageTone={messageTone}
            onRefresh={refreshAll}
            onCreateRequest={onCreateRequest}
          />
        )}
      </main>
    </div>
  );
}

export default App;
