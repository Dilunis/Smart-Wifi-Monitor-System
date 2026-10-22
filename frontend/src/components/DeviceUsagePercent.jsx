import { useEffect, useState } from "react";

/**
 * "Device usage" card — each device's quota use as a percentage bar.
 * Drop it next to the "Priority distribution" pie chart.
 *
 *     <DeviceUsagePercent token={token} />
 *
 * Reads GET /api/devices (already returns usage_percent per device — no new
 * backend endpoint needed). Refreshes every 5 seconds.
 */
const defaultBase = () => `${window.location.protocol}//${window.location.hostname}:5000`;

const c = {
  card: "#171b22", inner: "#0f131a", track: "#262c36", border: "#262c36",
  text: "#e6edf3", muted: "#8b949e",
  green: "#3fb950", amber: "#e3b341", red: "#f85149",
};

const barColor = (pct, throttled) => {
  if (pct >= 100) return c.red;
  if (pct >= 90) return c.red;
  if (pct >= 75) return c.amber;
  if (throttled) return c.amber;
  return c.green;
};

const priorityDot = { high: c.green, medium: "#58a6ff", low: c.amber };

export default function DeviceUsagePercent({ token, apiBase, devices: devicesProp }) {
  const base = apiBase || defaultBase();
  const [devices, setDevices] = useState(devicesProp || null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (devicesProp) { setDevices(devicesProp); return; } // parent already has the list
    let stop = false;
    const load = async () => {
      try {
        const res = await fetch(`${base}/api/devices`, { headers: { Authorization: `Bearer ${token}` } });
        const data = await res.json().catch(() => ({}));
        if (stop) return;
        if (!res.ok) return setError(data.message || `Request failed (${res.status})`);
        setDevices(data.devices || []);
        setError(null);
      } catch {
        if (!stop) setError(`Cannot reach the backend at ${base}.`);
      }
    };
    load();
    const id = setInterval(load, 5000);
    return () => { stop = true; clearInterval(id); };
  }, [base, token, devicesProp]);

  const sorted = [...(devices || [])].sort((a, b) => (b.usage_percent || 0) - (a.usage_percent || 0));

  return (
    <section style={{ background: c.card, border: `1px solid ${c.border}`, borderRadius: 16, padding: 24, color: c.text, fontFamily: "system-ui, sans-serif" }} aria-labelledby="usage-title">
      <h2 id="usage-title" style={{ margin: 0, fontSize: 20, fontWeight: 700 }}>Device usage</h2>
      <p style={{ margin: "6px 0 18px", color: c.muted, fontSize: 14 }}>Quota used, per device.</p>

      {error && <div role="alert" style={{ color: c.red, fontSize: 14, marginBottom: 12 }}>{error}</div>}

      {!devices && !error && <div style={{ color: c.muted, fontSize: 14 }}>Loading...</div>}

      {devices && devices.length === 0 && (
        <div style={{ color: c.muted, fontSize: 14 }}>No devices yet.</div>
      )}

      {devices && devices.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {sorted.map((d) => {
            const pct = Math.min(100, Math.max(0, d.usage_percent ?? 0));
            const color = barColor(pct, d.throttled);
            const usedGb = (d.used_quota_mb / 1024).toFixed(1);
            const totalGb = (d.total_quota_mb / 1024).toFixed(0);
            return (
              <div key={d.id}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 4, fontSize: 14 }}>
                  <span>
                    <span
                      aria-hidden="true"
                      style={{ display: "inline-block", width: 8, height: 8, borderRadius: 4, marginRight: 8, background: priorityDot[d.priority_level] || c.muted }}
                    />
                    {d.device_name}
                    {d.throttled && <span style={{ color: c.amber, fontSize: 12, marginLeft: 8 }}>throttled</span>}
                  </span>
                  <span style={{ color: c.muted }}>{usedGb} / {totalGb} GB &middot; {pct.toFixed(0)}%</span>
                </div>
                <div
                  role="progressbar"
                  aria-valuenow={Math.round(pct)}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-label={`${d.device_name} quota used`}
                  style={{ height: 8, borderRadius: 4, background: c.track, overflow: "hidden" }}
                >
                  <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 4, transition: "width .4s ease" }} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
