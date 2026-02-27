import { Router } from "express";
import { requireAuth } from "../middleware/auth.middleware.js";
import { requireRole } from "../middleware/role.middleware.js";
import { listUsersController, adminCreateUserController, adminUpdateUserController } from "../controllers/users.controller.js";

const router = Router();

// ADMIN ONLY ===============================================================
// GET /api/users
router.get("/", requireAuth, requireRole("ADMIN"), listUsersController);
// POST /api/users
router.post("/", requireAuth, requireRole("ADMIN"), adminCreateUserController);
// PATCH /api/users/:id
router.patch("/:id", requireAuth, requireRole("ADMIN"), adminUpdateUserController);
// END of ADMIN ONLY ========================================================

export default router;
