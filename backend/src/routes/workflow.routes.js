import { Router } from "express";
import { requireAuth } from "../middleware/auth.middleware.js";
import { requireRole } from "../middleware/role.middleware.js";
import { takeTaskController, forfeitTaskController, submitTaskController, rejectTaskController, approveTaskController } from "../controllers/workflow.controller.js";

const router = Router();

// Developer workflow
// POST api/tasks/:taskId/take
router.post("/tasks/:taskId/take", requireAuth, requireRole("DEVELOPER"), takeTaskController);
// POST api/tasks/:taskId/forfeit
router.post("/tasks/:taskId/forfeit", requireAuth, requireRole("DEVELOPER"), forfeitTaskController);
// POST api/tasks/:taskId/submit
router.post("/tasks/:taskId/submit", requireAuth, requireRole("DEVELOPER"), submitTaskController);

// Project Lead workflow
// POST api/tasks/:taskId/reject
router.post("/tasks/:taskId/reject", requireAuth, requireRole("PROJECT_LEAD"), rejectTaskController);
// POST api/tasks/:taskId/approve
router.post("/tasks/:taskId/approve", requireAuth, requireRole("PROJECT_LEAD"), approveTaskController);

export default router;
