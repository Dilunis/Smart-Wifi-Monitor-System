import React, { memo, useMemo, useState } from "react";
import { Pie } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";
import { formatGb, priorityLabel } from "../api";
import PriorityRequestModal from "./PriorityRequestModal";

ChartJS.register(ArcElement, Tooltip, Legend);

const PIE_OPTIONS = {
  plugins: { legend: { position: "bottom" } },
  maintainAspectRatio: false,
  animation: false,
};

const QuotaBar = memo(function QuotaBar({ used, total, alert }) {
  const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0;
  let tone = "ok";
  if (alert === "quota_warning") tone = "warn";
  if (alert === "quota_critical" || alert === "quota_exhausted") tone = "crit";
  return (
    <div className="quota-bar-wrap">
      <div className="quota-bar-meta">
        <span>{formatGb(used)} / {formatGb(total)}</span>
        <span>{pct.toFixed(0)}%</span>
      </div>
      <div className="quota-bar-track">
        <div className={`quota-bar-fill ${tone}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
});

const PriorityPie = memo(function PriorityPie({ data }) {
  return <Pie data={data} options={PIE_OPTIONS} />;
});

function AdminDashboardComponent({
  user,
  devices,
  requests,
  logs,
  policy,
  users,
  liveMonitor,
  setLiveMonitor,
  onRefresh,
  onAddDevice,
  onUpdateDevice,
  onRemoveDevice,
  onApprove,
  onReject,
  onExportCsv,
  message,
  messageTone,
}) {
  const [name, setName] = useState("");
  const [ip, setIp] = useState("");
  const [mac, setMac] = useState("");
  const [priority, setPriority] = useState("medium");
  const [ownerId, setOwnerId] = useState("");
  const [busy, setBusy] = useState(false);

  const pending = useMemo(
    () => requests.filter((r) => r.status === "pending"),
    [requests]
  );
  const unauthorized = useMemo(
    () => devices.filter((d) => d.status === "unauthorized"),
    [devices]
  );

  const pieData = useMemo(() => {
    const counts = { high: 0, medium: 0, low: 0 };
    devices.forEach((d) => {
      if (counts[d.priority_level] != null) counts[d.priority_level] += 1;
    });
    return {
      labels: ["High", "Medium", "Low"],
      datasets: [
        {
          data: [counts.high, counts.medium, counts.low],
          backgroundColor: ["#238636", "#1f6feb", "#9e6a03"],
          borderWidth: 0,
        },
      ],
    };
  }, [devices]);

  const handleAdd = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await onAddDevice({
        device_name: name,
        ip_address: ip,
        mac_address: mac,
        priority_level: priority,
        user_id: ownerId ? Number(ownerId) : null,
        status: "trusted",
      });
      setName("");
      setIp("");
      setMac("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="dashboard">
      {message && (
        <div className={`toast toast-${messageTone || "info"}`}>{message}</div>
      )}

      {unauthorized.length > 0 && (
        <div className="alert-banner">
          <strong>Unauthorized device detected:</strong>{" "}
          {unauthorized.map((d) => d.device_name).join(", ")} — review and block or assign an owner.
        </div>
      )}

      <div className="stats-row">
        <div className="stat-card">
          <span className="stat-label">Devices</span>
          <span className="stat-value">{devices.length}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Pending requests</span>
          <span className="stat-value">{pending.length}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Unauthorized</span>
          <span className="stat-value">{unauthorized.length}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Signed in</span>
          <span className="stat-value sm">{user.username}</span>
        </div>
      </div>

      <div className="grid-2">
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Connected devices</h2>
              <p>Quotas and QoS follow the priority policy engine.</p>
            </div>
            <div className="panel-actions">
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={liveMonitor}
                  onChange={(e) => setLiveMonitor(e.target.checked)}
                />
                Live usage tick
              </label>
              <button type="button" className="btn-secondary" onClick={onRefresh}>
                Refresh
              </button>
              <button type="button" className="btn-primary" onClick={onExportCsv}>
                Export CSV
              </button>
            </div>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Owner</th>
                  <th>Priority</th>
                  <th>Quota</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d.id} className={d.status === "unauthorized" ? "row-danger" : ""}>
                    <td>
                      <div className="cell-main">{d.device_name}</div>
                      <div className="cell-sub">{d.ip_address} · {d.mac_address}</div>
                      <div className="cell-sub">{d.qos_tag}{d.throttled ? " · THROTTLED" : ""}</div>
                    </td>
                    <td>{d.owner_username || "—"}</td>
                    <td>
                      <select
                        value={d.priority_level}
                        onChange={(e) =>
                          onUpdateDevice(d.id, {
                            priority_level: e.target.value,
                            renew_quota: true,
                          })
                        }
                      >
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                      </select>
                    </td>
                    <td style={{ minWidth: 160 }}>
                      <QuotaBar
                        used={d.used_quota_mb}
                        total={d.total_quota_mb}
                        alert={d.quota_alert}
                      />
                    </td>
                    <td>
                      <select
                        value={d.status}
                        onChange={(e) =>
                          onUpdateDevice(d.id, { status: e.target.value })
                        }
                      >
                        <option value="trusted">Trusted</option>
                        <option value="unauthorized">Unauthorized</option>
                        <option value="blocked">Blocked</option>
                        <option value="pending">Pending</option>
                      </select>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn-danger"
                        onClick={() => onRemoveDevice(d.id)}
                      >
                        Block
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Priority distribution</h2>
              <p>Devices by allocation tier</p>
            </div>
          </div>
          <div className="chart-box">
            <PriorityPie data={pieData} />
          </div>

          {policy && (
            <div className="policy-cards">
              {Object.entries(policy).map(([key, p]) => (
                <div key={key} className="policy-card">
                  <strong>{priorityLabel(key)}</strong>
                  <span>{p.quota_gb} GB / cycle</span>
                  <span>{p.qos_tag}</span>
                  <span>
                    {p.throttle_at_ratio == null
                      ? "Unthrottled"
                      : p.throttle_at_ratio === 0
                        ? "Always capped"
                        : `Throttle @ ${p.throttle_at_ratio * 100}%`}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      <div className="grid-2">
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Priority / access requests</h2>
              <p>Approve or reject client requests. High priority renews quota on approval.</p>
            </div>
          </div>
          {pending.length === 0 ? (
            <p className="empty">No pending requests.</p>
          ) : (
            <div className="request-list">
              {pending.map((r) => (
                <div key={r.id} className="request-item">
                  <div>
                    <strong>{r.username}</strong> · {r.device_name}
                    <div className="cell-sub">
                      {r.mac_address} · {r.ip_address}
                    </div>
                    <div className="cell-sub">
                      {r.current_priority} → <em>{r.requested_priority}</em>
                      {r.duration_hours ? ` · ${r.duration_hours}h` : ""}
                    </div>
                    <p className="reason">{r.reason}</p>
                    <div className="cell-sub">{r.created_at}</div>
                  </div>
                  <div className="request-actions">
                    <button type="button" className="btn-primary" onClick={() => onApprove(r.id)}>
                      Approve
                    </button>
                    <button type="button" className="btn-secondary" onClick={() => onReject(r.id)}>
                      Reject
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {requests.filter((r) => r.status !== "pending").length > 0 && (
            <>
              <h3 className="subhead">Recent decisions</h3>
              <ul className="history-list">
                {requests
                  .filter((r) => r.status !== "pending")
                  .slice(0, 8)
                  .map((r) => (
                    <li key={r.id}>
                      <span className={`pill ${r.status}`}>{r.status}</span>
                      {r.username} · {r.device_name} → {r.requested_priority}
                    </li>
                  ))}
              </ul>
            </>
          )}
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Register device</h2>
              <p>Add a trusted endpoint and assign an owner.</p>
            </div>
          </div>
          <form className="inline-form" onSubmit={handleAdd}>
            <input
              placeholder="Device name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
            <input
              placeholder="IP address"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
            />
            <input
              placeholder="MAC address"
              value={mac}
              onChange={(e) => setMac(e.target.value)}
              required
            />
            <select value={priority} onChange={(e) => setPriority(e.target.value)}>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select value={ownerId} onChange={(e) => setOwnerId(e.target.value)}>
              <option value="">No owner</option>
              {(users || [])
                .filter((u) => u.role === "user")
                .map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.username}
                  </option>
                ))}
            </select>
            <button type="submit" className="btn-primary" disabled={busy}>
              {busy ? "Adding…" : "Add device"}
            </button>
          </form>

          <h3 className="subhead">Activity log</h3>
          <div className="log-terminal">
            {logs.length === 0 && <div>No events yet.</div>}
            {logs.map((l) => (
              <div key={l.id}>
                [{l.created_at}] {l.message}
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

function ClientPortalComponent({
  user,
  devices,
  requests,
  policy,
  onCreateRequest,
  onRefresh,
  message,
  messageTone,
}) {
  const [showModal, setShowModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (payload) => {
    setSubmitting(true);
    try {
      await onCreateRequest(payload);
      setShowModal(false);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="dashboard">
      {message && (
        <div className={`toast toast-${messageTone || "info"}`}>{message}</div>
      )}

      <div className="panel-header page-intro">
        <div>
          <h2>My network portal</h2>
          <p>
            Welcome, {user.username}. Track your devices, remaining quota, and
            submit priority / access requests.
          </p>
        </div>
        <div className="panel-actions">
          <button type="button" className="btn-secondary" onClick={onRefresh}>
            Refresh
          </button>
          <button
            type="button"
            className="btn-primary"
            onClick={() => setShowModal(true)}
            disabled={devices.length === 0}
          >
            Request priority / access
          </button>
        </div>
      </div>

      {policy && (
        <div className="policy-cards">
          {Object.entries(policy).map(([key, p]) => (
            <div key={key} className="policy-card">
              <strong>{priorityLabel(key)}</strong>
              <span>{p.quota_gb} GB / cycle</span>
              <span>{p.qos_tag}</span>
            </div>
          ))}
        </div>
      )}

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>My devices</h2>
            <p>Usage is tracked server-side against your assigned quota.</p>
          </div>
        </div>
        {devices.length === 0 ? (
          <p className="empty">
            No devices are registered to your account. Ask an admin to assign one.
          </p>
        ) : (
          <div className="device-cards">
            {devices.map((d) => (
              <div key={d.id} className="device-card">
                <div className="device-card-top">
                  <h3>{d.device_name}</h3>
                  <span className={`pill ${d.priority_level}`}>{d.priority_level}</span>
                </div>
                <div className="cell-sub">{d.ip_address} · {d.mac_address}</div>
                <div className="cell-sub">{d.qos_tag}</div>
                <QuotaBar
                  used={d.used_quota_mb}
                  total={d.total_quota_mb}
                  alert={d.quota_alert}
                />
                <div className="device-meta">
                  <span>Remaining: {formatGb(d.remaining_quota_mb)}</span>
                  <span>{d.throttled ? "Throttled" : "Full rate"}</span>
                  <span className={`pill ${d.status}`}>{d.status}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>My requests</h2>
            <p>Admins are emailed when you submit a new request.</p>
          </div>
        </div>
        {requests.length === 0 ? (
          <p className="empty">You have not submitted any requests yet.</p>
        ) : (
          <ul className="history-list">
            {requests.map((r) => (
              <li key={r.id}>
                <span className={`pill ${r.status}`}>{r.status}</span>
                {r.device_name} → {r.requested_priority}
                <span className="cell-sub"> · {r.created_at}</span>
                <div className="reason">{r.reason}</div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {showModal && (
        <PriorityRequestModal
          devices={devices}
          onClose={() => setShowModal(false)}
          onSubmit={handleSubmit}
          submitting={submitting}
        />
      )}
    </div>
  );
}

const AdminDashboard = memo(AdminDashboardComponent);
const ClientPortal = memo(ClientPortalComponent);

export { AdminDashboard, ClientPortal, QuotaBar };
