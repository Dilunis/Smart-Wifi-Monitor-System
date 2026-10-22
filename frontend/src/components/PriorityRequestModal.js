import React, { useState } from "react";

function PriorityRequestModal({ devices, onClose, onSubmit, submitting }) {
  const [deviceId, setDeviceId] = useState(devices[0]?.id || "");
  const [requestedPriority, setRequestedPriority] = useState("high");
  const [durationHours, setDurationHours] = useState("24");
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!deviceId) {
      setError("Select a device.");
      return;
    }
    if (!reason.trim()) {
      setError("Please provide a justification.");
      return;
    }
    try {
      await onSubmit({
        device_id: Number(deviceId),
        requested_priority: requestedPriority,
        duration_hours: durationHours ? Number(durationHours) : null,
        reason: reason.trim(),
      });
    } catch (err) {
      setError(err.message || "Failed to submit request");
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose} role="presentation">
      <div
        className="modal-card"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-labelledby="request-modal-title"
      >
        <div className="modal-header">
          <h3 id="request-modal-title">Request Network Access / High Priority</h3>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <form onSubmit={handleSubmit} className="modal-form">
          <label htmlFor="req-device">Device</label>
          <select
            id="req-device"
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
            required
          >
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.device_name} ({d.priority_level}) — {d.mac_address}
              </option>
            ))}
          </select>

          <label htmlFor="req-priority">Requested priority</label>
          <select
            id="req-priority"
            value={requestedPriority}
            onChange={(e) => setRequestedPriority(e.target.value)}
          >
            <option value="high">High — 50 GB, unthrottled, mission-critical QoS</option>
            <option value="medium">Medium — 20 GB, throttle after 90%</option>
            <option value="low">Low — 5 GB, capped (guests / IoT)</option>
          </select>

          <label htmlFor="req-duration">Duration (hours)</label>
          <input
            id="req-duration"
            type="number"
            min="1"
            max="720"
            value={durationHours}
            onChange={(e) => setDurationHours(e.target.value)}
          />

          <label htmlFor="req-reason">Justification</label>
          <textarea
            id="req-reason"
            rows={4}
            placeholder="Explain why you need elevated access or priority…"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            required
          />

          {error && <div className="form-error">{error}</div>}

          <div className="modal-actions">
            <button type="button" className="btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={submitting}>
              {submitting ? "Submitting…" : "Submit request"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default PriorityRequestModal;
