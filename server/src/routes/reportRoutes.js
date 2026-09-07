import { Router } from "express";
import { requireAuth, requireRole } from "../middleware/auth.js";
import {
  submitReport,
  getReportByTrackingId,
  getAssignedReports,
  updateReportStatus,
  reassignReport,
} from "../controllers/reportController.js";

const router = Router();

// Public — no auth required (supports fully anonymous submission)
router.post("/", submitReport);
router.get("/track/:trackingId", getReportByTrackingId);

// Reviewer-only
router.get("/assigned", requireAuth, requireRole("reviewer"), getAssignedReports);
router.patch("/:id/status", requireAuth, requireRole("reviewer"), updateReportStatus);

// Admin-only
router.patch("/:id/assign", requireAuth, requireRole("admin"), reassignReport);

export default router;