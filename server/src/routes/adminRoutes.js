import { Router } from "express";
import { requireAuth, requireRole } from "../middleware/auth.js";
import { createReviewer, listReviewers, rotateReviewerKeys, getAuditLogs } from "../controllers/adminController.js";

const router = Router();

router.post("/reviewers", requireAuth, requireRole("admin"), createReviewer);
router.get("/reviewers", requireAuth, requireRole("admin"), listReviewers);
router.post("/reviewers/:id/rotate-keys", requireAuth, requireRole("admin"), rotateReviewerKeys);
router.get("/audit-logs", requireAuth, requireRole("admin"), getAuditLogs);

export default router;