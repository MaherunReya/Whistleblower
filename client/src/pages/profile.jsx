import { useEffect, useState } from "react";
import api from "../api/axios.js";

export default function Profile() {
  const [form, setForm] = useState({ email: "", contactInfo: "" });
  const [username, setUsername] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    api
      .get("/auth/profile")
      .then(({ data }) => {
        setUsername(data.username);
        setForm({ email: data.email || "", contactInfo: data.contactInfo || "" });
      })
      .catch((err) => setError(err.response?.data?.error || "Failed to load profile"))
      .finally(() => setLoading(false));
  }, []);

  function update(field) {
    return (e) => setForm((f) => ({ ...f, [field]: e.target.value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setSuccess("");
    setSaving(true);
    try {
      await api.patch("/auth/profile", form);
      setSuccess("Profile updated.");
    } catch (err) {
      setError(err.response?.data?.error || "Failed to update profile");
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <div className="page-loading">Loading…</div>;

  return (
    <div className="page-narrow">
      <div className="card">
        <h1 className="card-title">My Profile</h1>
        <p className="card-subtitle">
          Email and contact info are encrypted before storage and decrypted only for you here.
        </p>
        <form onSubmit={handleSubmit} className="form">
          <label>
            Username
            <input value={username} disabled />
          </label>
          <label>
            Email
            <input type="email" value={form.email} onChange={update("email")} required />
          </label>
          <label>
            Contact Info
            <input value={form.contactInfo} onChange={update("contactInfo")} />
          </label>
          {error && <p className="form-error">{error}</p>}
          {success && <p className="form-success">{success}</p>}
          <button className="btn btn-primary" disabled={saving}>
            {saving ? "Saving…" : "Save Changes"}
          </button>
        </form>
      </div>
    </div>
  );
}