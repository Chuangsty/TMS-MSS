import { Router } from "express";
import { listTasksController, createTaskController, updateTaskController, createPlanController } from "../controllers/taskDash.controller.js";
import { requireAuth } from "../middleware/auth.middleware.js";
import { requireRole } from "../middleware/role.middleware.js";

const router = Router();

// TASK features ======================================================================================
// GET /api/apps/:appAcronym/tasks
router.get("/apps/:appAcronym/tasks", requireAuth, listTasksController);
// POST /api/apps/:appId/tasks
router.post("/apps/:appAcronym/tasks", requireAuth, requireRole("PROJECT_LEAD"), createTaskController);
// PATCH /api/tasks/:taskId
router.patch("/tasks/:taskId", requireAuth, requireRole("PROJECT_LEAD"), updateTaskController);

// PLAN features ======================================================================================
// POST /api/apps/:appId/plan
router.post("/apps/:appAcronym/plan", requireAuth, requireRole("PROJECT_MANAGER"), createPlanController);

export default router;
