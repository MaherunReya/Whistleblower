import { Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar.jsx";
import Login from "./pages/Login.jsx";
import Register from "./pages/Register.jsx";
import SubmitReport from "./pages/SubmitReport.jsx";
import TrackReport from "./pages/TrackReport.jsx";
import ReviewerDashboard from "./pages/ReviewerDashboard.jsx";
import AdminDashboard from "./pages/AdminDashboard.jsx";
import Profile from "./pages/Profile.jsx";
import ChangePassword from "./pages/ChangePassword.jsx";
import ProtectedRoute from "./components/ProtectedRoute.jsx";

export default function App() {
  return (
    <div className="app-shell">
      <Navbar />
      <main className="app-content">
        <Routes>
          <Route path="/" element={<SubmitReport />} />
          <Route path="/track" element={<TrackReport />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          <Route
            path="/reviewer"
            element={
              <ProtectedRoute role="reviewer">
                <ReviewerDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin"
            element={
              <ProtectedRoute role="admin">
                <AdminDashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/profile"
            element={
              <ProtectedRoute role="admin">
                <Profile />
              </ProtectedRoute>
            }
          />
          <Route
            path="/change-password"
            element={
              <ProtectedRoute>
                <ChangePassword />
              </ProtectedRoute>
            }
          />
        </Routes>
      </main>
    </div>
  );
}