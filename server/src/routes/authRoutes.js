import { Router } from "express";
import { requireAuth, requireRole } from "../middleware/auth.js";
import {
  register,
  login,
  verify2FA,
  setup2FA,
  confirm2FA,
  logout,
  getMe,
  getProfile,
  updateProfile,
  changePassword,
} from "../controllers/authController.js";

const router = Router();

router.post("/register", register);
router.post("/login", login);
router.post("/verify-2fa", verify2FA);
router.post("/setup-2fa", requireAuth, setup2FA);
router.post("/confirm-2fa", requireAuth, confirm2FA);
router.post("/logout", logout);
router.get("/me", requireAuth, getMe);
router.get("/profile", requireAuth, requireRole("admin"), getProfile);
router.patch("/profile", requireAuth, requireRole("admin"), updateProfile);
router.patch("/password", requireAuth, changePassword);

export default router;