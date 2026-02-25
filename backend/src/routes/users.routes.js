import { Router } from "express";
import { requireAuth } from "../middleware/auth.middleware.js";
import { requireRole } from "../middleware/role.middleware.js";

const router = Router();

/*
GET /api/users/me (protected)
Any authenticated user can view their own profile/page */
router.get("/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

/*
GET /api/users
Only ADMIN can list all users */
router.get("/", requireAuth, requireRole("ADMIN"), (req, res) => {
  res.json({ message: "List users (ADMIN only)" });
});

export default router;
