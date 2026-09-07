import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../api/axios.js";
import { useAuth } from "../context/AuthContext.jsx";

export default function ChangePassword() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const { user, setUser } = useAuth();
  const navigate = useNavigate();

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    if (newPassword !== confirmPassword) {
      setError("New passwords don't match");
      return;
    }
    setLoading(true);
    try {
      await api.patch("/auth/password", { currentPassword, newPassword });
      setUser((u) => ({ ...u, mustChangePassword: false }));
      navigate(user?.role === "admin" ? "/admin" : "/reviewer");
    } catch (err) {
      setError(err.response?.data?.error || "Failed to change password");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page-narrow">
      <div className="card">
        <h1 className="card-title">Set a New Password</h1>
        <p className="card-subtitle">
          {user?.mustChangePassword
            ? "Your account was created with a temporary password. Set your own before continuing."
            : "Change your account password."}
        </p>
        <form onSubmit={handleSubmit} className="form">
          <label>
            Current Password
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
              autoFocus
            />
          </label>
          <label>
            New Password
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              minLength={8}
            />
          </label>
          <label>
            Confirm New Password
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              minLength={8}
            />
          </label>
          {error && <p className="form-error">{error}</p>}
          <button className="btn btn-primary" disabled={loading}>
            {loading ? "Saving…" : "Set New Password"}
          </button>
        </form>
      </div>
    </div>
  );
}