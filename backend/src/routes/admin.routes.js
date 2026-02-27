import { Router } from "express";
import { requireAuth } from "../middleware/auth.middleware.js";
import { requireRole } from "../middleware/role.middleware.js";
import { listUsersController, adminCreateUserController, adminUpdateUserController } from "../controllers/admin.controller.js";

const router = Router();

// ADMIN ONLY ===============================================================
router.use(requireAuth, requireRole("ADMIN"));
// GET /api/admin
router.get("/", listUsersController);
// POST /api/admin/new_user
router.post("/new_user", adminCreateUserController);
// PATCH /api/admin/user/:id
router.patch("/user/:id", adminUpdateUserController);
// END of ADMIN ONLY ========================================================

export default router;
