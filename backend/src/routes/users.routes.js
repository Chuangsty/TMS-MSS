import { Router } from "express";
import { requireAuth } from "../middleware/auth.middleware.js";
import { requireRole } from "../middleware/role.middleware.js";
import { listUsersController, createUserController, userStatusController, resetUserPasswordController } from "../controllers/users.controller.js";

const router = Router();

// ADMIN ONLY ===============================================================
// GET /api/users
router.get("/", requireAuth, requireRole("ADMIN"), listUsersController);
// POST /api/users
router.post("/", requireAuth, requireRole("ADMIN"), createUserController);
// PATCH /api/users/:id/disable --- Disable
router.patch("/:id/disable", requireAuth, requireRole("ADMIN"), (req, res, next) => userStatusController("DISABLED")(req, res, next));
// PATCH /api/users/:id/enable --- Enable
router.patch("/:id/enable", requireAuth, requireRole("ADMIN"), (req, res, next) => userStatusController("ACTIVE")(req, res, next));
// PATCH /api/users/:id/reset-password
router.patch("/:id/reset-password", requireAuth, requireRole("ADMIN"), resetUserPasswordController);
// END of ADMIN ONLY ========================================================

/*
GET /api/users/me (protected)
Any authenticated user can view their own profile/page */
// router.get("/me", requireAuth, (req, res) => {
//   res.json({ user: req.user });
// });

// /*
// GET /api/users
// Only ADMIN can list all users */
// router.get("/", requireAuth, requireRole("ADMIN"), (req, res) => {
//   res.json({ message: "List users (ADMIN only)" });
// });

export default router;
