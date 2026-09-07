import { useEffect, useState } from "react";
import api from "../api/axios.js";

export default function AdminDashboard() {
  const [form, setForm] = useState({ username: "", password: "", email: "" });
  const [createError, setCreateError] = useState("");
  const [createSuccess, setCreateSuccess] = useState("");
  const [creating, setCreating] = useState(false);

  const [reviewers, setReviewers] = useState([]);
  const [reviewersLoading, setReviewersLoading] = useState(true);
  const [reviewersError, setReviewersError] = useState("");

  const [rotateId, setRotateId] = useState("");
  const [rotateError, setRotateError] = useState("");
  const [rotateSuccess, setRotateSuccess] = useState("");
  const [rotating, setRotating] = useState(false);

  const [reassignReportId, setReassignReportId] = useState("");
  const [reassignReviewerId, setReassignReviewerId] = useState("");
  const [reassignError, setReassignError] = useState("");
  const [reassignSuccess, setReassignSuccess] = useState("");
  const [reassigning, setReassigning] = useState(false);

  const [logs, setLogs] = useState([]);
  const [chainIntact, setChainIntact] = useState(null);
  const [logsLoading, setLogsLoading] = useState(true);
  const [logsError, setLogsError] = useState("");

  async function loadReviewers() {
    setReviewersLoading(true);
    setReviewersError("");
    try {
      const { data } = await api.get("/admin/reviewers");
      setReviewers(data);
    } catch (err) {
      setReviewersError(err.response?.data?.error || "Failed to load reviewers");
    } finally {
      setReviewersLoading(false);
    }
  }

  async function loadLogs() {
    setLogsLoading(true);
    setLogsError("");
    try {
      const { data } = await api.get("/admin/audit-logs");
      setLogs(data.logs);
      setChainIntact(data.chainIntact);
    } catch (err) {
      setLogsError(err.response?.data?.error || "Failed to load audit logs");
    } finally {
      setLogsLoading(false);
    }
  }

  useEffect(() => {
    loadReviewers();
    loadLogs();
  }, []);

  function update(field) {
    return (e) => setForm((f) => ({ ...f, [field]: e.target.value }));
  }

  async function handleCreate(e) {
    e.preventDefault();
    setCreateError("");
    setCreateSuccess("");
    setCreating(true);
    try {
      const { data } = await api.post("/admin/reviewers", form);
      setCreateSuccess(
        `Reviewer "${data.username}" created with a temporary password — they'll be asked to set their own on first login.`
      );
      setForm({ username: "", password: "", email: "" });
      loadReviewers();
      loadLogs();
    } catch (err) {
      setCreateError(err.response?.data?.error || "Failed to create reviewer");
    } finally {
      setCreating(false);
    }
  }

  async function handleRotate(e) {
    e.preventDefault();
    setRotateError("");
    setRotateSuccess("");
    setRotating(true);
    try {
      await api.post(`/admin/reviewers/${rotateId}/rotate-keys`);
      setRotateSuccess("Keys rotated successfully.");
      loadLogs();
    } catch (err) {
      setRotateError(err.response?.data?.error || "Failed to rotate keys");
    } finally {
      setRotating(false);
    }
  }

  async function handleReassign(e) {
    e.preventDefault();
    setReassignError("");
    setReassignSuccess("");
    setReassigning(true);
    try {
      await api.patch(`/reports/${reassignReportId.trim()}/assign`, { reviewerId: reassignReviewerId });
      setReassignSuccess("Report reassigned successfully.");
      setReassignReportId("");
      loadReviewers();
      loadLogs();
    } catch (err) {
      setReassignError(err.response?.data?.error || "Failed to reassign report");
    } finally {
      setReassigning(false);
    }
  }

  return (
    <div className="page-wide">
      <h1 className="page-title">Admin Dashboard</h1>

      <div className="admin-grid">
        <div className="card">
          <h2 className="card-title">Create Reviewer</h2>
          <form onSubmit={handleCreate} className="form">
            <label>
              Username
              <input value={form.username} onChange={update("username")} required />
            </label>
            <label>
              Temporary Password
              <input type="password" value={form.password} onChange={update("password")} required minLength={8} />
            </label>
            <label>
              Email
              <input type="email" value={form.email} onChange={update("email")} required />
            </label>
            {createError && <p className="form-error">{createError}</p>}
            {createSuccess && <p className="form-success">{createSuccess}</p>}
            <button className="btn btn-primary" disabled={creating}>
              {creating ? "Creating…" : "Create Reviewer"}
            </button>
          </form>
        </div>

        <div className="card">
          <h2 className="card-title">Rotate Reviewer Keys</h2>
          <p className="card-subtitle">Old keys stay retired-but-stored, so past reports remain decryptable.</p>
          <form onSubmit={handleRotate} className="form">
            <label>
              Reviewer
              <select value={rotateId} onChange={(e) => setRotateId(e.target.value)} required>
                <option value="" disabled>
                  {reviewersLoading ? "Loading…" : "Select a reviewer"}
                </option>
                {reviewers.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.username} ({r.openReportCount} open)
                  </option>
                ))}
              </select>
            </label>
            {reviewersError && <p className="form-error">{reviewersError}</p>}
            {rotateError && <p className="form-error">{rotateError}</p>}
            {rotateSuccess && <p className="form-success">{rotateSuccess}</p>}
            <button className="btn btn-secondary" disabled={rotating || !rotateId}>
              {rotating ? "Rotating…" : "Rotate Keys"}
            </button>
          </form>
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">Reassign a Report</h2>
        <p className="card-subtitle">
          Content is re-encrypted for the new reviewer server-side — you never see the report itself.
        </p>
        <form onSubmit={handleReassign} className="form">
          <label>
            Report ID
            <input
              value={reassignReportId}
              onChange={(e) => setReassignReportId(e.target.value)}
              placeholder="Mongo _id of the report"
              required
            />
          </label>
          <label>
            New Reviewer
            <select
              value={reassignReviewerId}
              onChange={(e) => setReassignReviewerId(e.target.value)}
              required
            >
              <option value="" disabled>
                {reviewersLoading ? "Loading…" : "Select a reviewer"}
              </option>
              {reviewers.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.username} ({r.openReportCount} open)
                </option>
              ))}
            </select>
          </label>
          {reassignError && <p className="form-error">{reassignError}</p>}
          {reassignSuccess && <p className="form-success">{reassignSuccess}</p>}
          <button className="btn btn-secondary" disabled={reassigning}>
            {reassigning ? "Reassigning…" : "Reassign"}
          </button>
        </form>
      </div>

      <div className="card">
        <h2 className="card-title">Reviewers</h2>
        {reviewersLoading && <p>Loading…</p>}
        {!reviewersLoading && reviewers.length === 0 && (
          <p className="empty-state">No reviewer accounts yet.</p>
        )}
        {!reviewersLoading && reviewers.length > 0 && (
          <table className="audit-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Open Reports</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {reviewers.map((r) => (
                <tr key={r.id}>
                  <td>{r.username}</td>
                  <td>{r.openReportCount}</td>
                  <td>{new Date(r.createdAt).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <div className="card-header-row">
          <h2 className="card-title">Audit Log</h2>
          {chainIntact !== null && (
            <span className={`status-badge ${chainIntact ? "status-success" : "status-danger"}`}>
              {chainIntact ? "Chain Intact" : "Chain Broken"}
            </span>
          )}
        </div>
        {logsLoading && <p>Loading…</p>}
        {logsError && <p className="form-error">{logsError}</p>}
        {!logsLoading && logs.length > 0 && (
          <table className="audit-table">
            <thead>
              <tr>
                <th>Action</th>
                <th>Performed By</th>
                <th>Target</th>
                <th>Timestamp</th>
                <th>MAC</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((l) => (
                <tr key={l._id} className={l.macValid ? "" : "row-invalid"}>
                  <td>{l.action}</td>
                  <td>{l.performedBy || "—"}</td>
                  <td>{l.targetId || "—"}</td>
                  <td>{new Date(l.timestamp).toLocaleString()}</td>
                  <td>{l.macValid ? "✓" : "✗ tampered"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!logsLoading && logs.length === 0 && <p className="empty-state">No audit entries yet.</p>}
      </div>
    </div>
  );
}