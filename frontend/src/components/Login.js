import React, { useState } from "react";
import "./Login.css";

function Login({ onLogin, error, loading }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    onLogin(username.trim(), password);
  };

  return (
    <div className="login-page">
      <div className="login-panel">
        <div className="login-brand">
          <span className="login-mark">SW</span>
          <div>
            <h1>Smart WiFi Monitor</h1>
            <p>CoreRouter OS · Network Control Center</p>
          </div>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <h2>Sign in</h2>
          <p className="login-hint">
            Use your admin or client account to continue.
          </p>

          <label htmlFor="username">Username</label>
          <input
            id="username"
            type="text"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />

          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          {error && <div className="login-error">{error}</div>}

          <button type="submit" disabled={loading}>
            {loading ? "Authenticating…" : "Authenticate"}
          </button>
        </form>

        <div className="login-credentials">
          <strong>Demo accounts</strong>
          <span>Admin — admin / Admin@123</span>
          <span>Client — client / Client@123</span>
          <span>Guest — guest / Guest@123</span>
        </div>
      </div>
    </div>
  );
}

export default Login;
