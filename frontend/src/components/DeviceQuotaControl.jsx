import { useState } from "react";

/**
 * Priority + Quota editor for one device row in the admin dashboard.
 *
 *     <DeviceQuotaControl token={token} device={device} onUpdated={(d) => ...} />
 *
 * - Priority select: high / medium / low.
 * - Quota select: 1, 2, 3, 4, 5, 6, 7, 8, 10 GB (matches the backend's allowed list).
 * - Changing either one keeps the device's used quota as-is (only capped if it now
 *   exceeds the new total) — it does NOT reset usage to 0.
 * - "Reset quota" is a separate, explicit button for when you actually want to zero it.
 *
 * apiBase defaults to the same host this page was opened from, on port 5000.
 */
const defaultBase = () => `${window.location.protocol}//${window.location.hostname}:5000`;

const QUOTA_OPTIONS_GB = [1, 2, 3, 4, 5, 6, 7, 8, 10];
const PRIORITIES = [
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const c = {
  border: "#262c36", input: "#0b0e14", text: "#e6edf3", muted: "#8b949e",
  green: "#3fb950", red: "#ff8b8b",
};
const s = {
  row: { display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10, fontFamily: "system-ui, sans-serif" },
  select: { padding: "8px 10px", borderRadius: 8, border: `1px solid ${c.border}`, background: c.input, color: c.text, fontSize: 14 },
  btn: { padding: "8px 12px", borderRadius: 8, border: `1px solid ${c.border}`, background: "transparent", color: c.text, fontSize: 13, cursor: "pointer" },
  hint: { fontSize: 12, color: c.muted, width: "100%" },
};

// device.total_quota_mb is always a multiple of 1024 in practice (GB steps), but guard anyway.
const closestQuotaGb = (mb) => {
  const gb = mb / 1024;
  return QUOTA_OPTIONS_GB.reduce((best, v) => (Math.abs(v - gb) < Math.abs(best - gb) ? v : best), QUOTA_OPTIONS_GB[0]);
};

export default function DeviceQuotaControl({ token, device, apiBase, onUpdated }) {
  const base = apiBase || defaultBase();
  const [priority, setPriority] = useState(device.priority_level);
  const [quotaGb, setQuotaGb] = useState(closestQuotaGb(device.total_quota_mb));
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null); // { text, ok }

  const patch = async (body, note) => {
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch(`${base}/api/devices/${device.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setMsg({ text: data.message || "Update failed.", ok: false });
        return;
      }
      setMsg({ text: note, ok: true });
      onUpdated?.(data.device);
    } catch {
      setMsg({ text: `Cannot reach the backend at ${base}.`, ok: false });
    } finally {
      setBusy(false);
    }
  };

  const changePriority = (value) => {
    setPriority(value);
    patch({ priority_level: value }, `Priority set to ${value}. Usage kept.`);
  };

  const changeQuota = (value) => {
    const gb = Number(value);
    setQuotaGb(gb);
    patch({ quota_gb: gb }, `Quota set to ${gb} GB. Usage kept.`);
  };

  const resetUsage = () => {
    if (!window.confirm(`Reset ${device.device_name}'s used data back to 0?`)) return;
    patch({ used_quota_mb: 0 }, "Usage reset to 0.");
  };

  return (
    <div style={s.row}>
      <label>
        <span style={{ ...s.hint, width: "auto", marginRight: 6 }}>Priority</span>
        <select style={s.select} value={priority} disabled={busy} onChange={(e) => changePriority(e.target.value)}>
          {PRIORITIES.map((p) => (
            <option key={p.value} value={p.value}>{p.label}</option>
          ))}
        </select>
      </label>

      <label>
        <span style={{ ...s.hint, width: "auto", marginRight: 6 }}>Quota</span>
        <select style={s.select} value={quotaGb} disabled={busy} onChange={(e) => changeQuota(e.target.value)}>
          {QUOTA_OPTIONS_GB.map((g) => (
            <option key={g} value={g}>{g} GB</option>
          ))}
        </select>
      </label>

      <button type="button" style={{ ...s.btn, opacity: busy ? 0.6 : 1 }} disabled={busy} onClick={resetUsage}>
        Reset usage to 0
      </button>

      {msg && <span style={{ ...s.hint, width: "auto", color: msg.ok ? c.green : c.red }}>{msg.text}</span>}
    </div>
  );
}
