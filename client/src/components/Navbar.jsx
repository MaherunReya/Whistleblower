import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import api from "../api/axios.js";

export default function Navbar() {
  const { user, setUser } = useAuth();
  const navigate = useNavigate();

  async function handleLogout() {
    try {
      await api.post("/auth/logout");
    } finally {
      setUser(null);
      navigate("/");
    }
  }

  return (
    <header className="navbar">
      <div className="navbar-inner">
        <Link to="/" className="navbar-brand">
          Whistleblower Portal
        </Link>
        <nav className="navbar-links">
          <Link to="/">Submit Report</Link>
          <Link to="/track">Track Report</Link>
          {!user && <Link to="/login">Login</Link>}
          {!user && <Link to="/register">Register</Link>}
          {user?.role === "reviewer" && <Link to="/reviewer">Reviewer Dashboard</Link>}
          {user?.role === "admin" && <Link to="/admin">Admin Dashboard</Link>}
          {user?.role === "admin" && <Link to="/profile">My Profile</Link>}
          {user && (
            <>
              <Link to="/change-password">Change Password</Link>
              <span className="navbar-user">
                {user.username} · {user.role}
              </span>
              <button className="btn btn-ghost" onClick={handleLogout}>
                Logout
              </button>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}