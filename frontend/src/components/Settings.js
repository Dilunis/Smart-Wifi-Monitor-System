import React, { useEffect, useState } from "react";
import { api } from "../api";

function Settings({ onMessage }) {
  const [wifiName, setWifiName] = useState("");
  const [wifiPassword, setWifiPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [securityType, setSecurityType] = useState("WPA3-Personal");
  const [passwordSet, setPasswordSet] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await api.getRouterSettings();
        if (cancelled) return;
        const s = data.settings || {};
        setWifiName(s.wifi_name || "");
        setSecurityType(s.security_type || "WPA3-Personal");
        setPasswordSet(Boolean(s.wifi_password_set));
        setWifiPassword("");
        setConfirmPassword("");
      } catch (err) {
        onMessage?.(err.message || "Failed to load Wi-Fi settings", "danger");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [onMessage]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError("");

    const ssid = wifiName.trim();
    if (!ssid) {
      setFormError("Network name (SSID) is required.");
      return;
    }
    if (ssid.length > 32) {
      setFormError("SSID must be 32 characters or fewer.");
      return;
    }

    const pwd = wifiPassword.trim();
    const confirm = confirmPassword.trim();
    if (pwd || confirm) {
      if (pwd.length < 8) {
        setFormError("Wi-Fi password must be at least 8 characters.");
        return;
      }
      if (pwd !== confirm) {
        setFormError("Password and confirmation do not match.");
        return;
      }
    }

    setSaving(true);
    try {
      const payload = {
        wifiName: ssid,
        securityType,
      };
      if (pwd) {
        payload.wifiPassword = pwd;
      }
      const data = await api.updateRouterSettings(payload);
      setPasswordSet(Boolean(data.settings?.wifi_password_set) || passwordSet || Boolean(pwd));
      setWifiPassword("");
      setConfirmPassword("");
      setShowPassword(false);
      onMessage?.(data.message || "Wi-Fi settings updated successfully", "success");
    } catch (err) {
      const msg = err.message || "Failed to update Wi-Fi settings";
      setFormError(msg);
      onMessage?.(msg, "danger");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="panel settings-panel">
        <p className="empty">Loading Wi-Fi settings…</p>
      </div>
    );
  }

  return (
    <div className="wifi-settings-page">
      <div className="panel settings-panel">
        <div className="panel-header">
          <div>
            <h2>Wi-Fi Settings</h2>
            <p>
              Router panel — view and update SSID, security protocol, and Wi-Fi
              password. Changes are encrypted at rest (admin only).
            </p>
          </div>
          <span className={`pill ${passwordSet ? "trusted" : "pending"}`}>
            {passwordSet ? "Password set" : "No password"}
          </span>
        </div>

        <form className="settings-form wifi-settings-form" onSubmit={handleSubmit}>
          <label htmlFor="wifi-name">Network Name (SSID)</label>
          <input
            id="wifi-name"
            type="text"
            maxLength={32}
            value={wifiName}
            onChange={(e) => setWifiName(e.target.value)}
            placeholder="e.g. Smart_WiFi_Gateway"
            required
            autoComplete="off"
          />

          <label htmlFor="wifi-sec">Security Protocol</label>
          <select
            id="wifi-sec"
            value={securityType}
            onChange={(e) => setSecurityType(e.target.value)}
          >
            <option value="WPA3-Personal">WPA3-Personal</option>
            <option value="WPA2-PSK">WPA2-PSK</option>
          </select>

          <label htmlFor="wifi-pass">Wi-Fi Password</label>
          <div className="password-field">
            <input
              id="wifi-pass"
              type={showPassword ? "text" : "password"}
              placeholder={
                passwordSet
                  ? "Leave blank to keep current password"
                  : "Enter a new Wi-Fi password"
              }
              value={wifiPassword}
              onChange={(e) => setWifiPassword(e.target.value)}
              autoComplete="new-password"
              minLength={wifiPassword ? 8 : undefined}
            />
            <button
              type="button"
              className="btn-secondary password-toggle"
              onClick={() => setShowPassword((v) => !v)}
              aria-label={showPassword ? "Hide password" : "Show password"}
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>

          <label htmlFor="wifi-pass-confirm">Confirm Wi-Fi Password</label>
          <input
            id="wifi-pass-confirm"
            type={showPassword ? "text" : "password"}
            placeholder="Re-enter password if changing"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            autoComplete="new-password"
          />
          <p className="field-hint">
            Minimum 8 characters when setting or changing the password. Current
            password is never shown (stored encrypted as ********).
          </p>

          {formError && <div className="form-error">{formError}</div>}

          <button type="submit" className="btn-primary" disabled={saving}>
            {saving ? "Updating…" : "Update Wi-Fi Settings"}
          </button>
        </form>
      </div>
    </div>
  );
}

export default Settings;
