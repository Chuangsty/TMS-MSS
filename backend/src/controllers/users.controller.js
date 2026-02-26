import { Router } from "express";
import { listUsersService, createUserService, userStatusService, resetUserPasswordService } from "../services/users.service.js";

const router = Router();

// Admin: Users List
export async function listUsersController(req, res, next) {
  try {
    const result = await listUsersService(); // or pass filters if you have
    res.json(result);
  } catch (err) {
    next(err);
  }
}

// ADMIN: User Creation
export async function createUserController(req, res, next) {
  try {
    const { username, email, password, roles } = req.body;

    const result = await createUserService({ username, email, password, roles });

    res.status(201).json(result);
  } catch (err) {
    next(err);
  }
}

// ADMIN: User Status Control
export function userStatusController(statusSlug) {
  return async (req, res, next) => {
    try {
      // target user id from URL param (string → number)
      const targetUserId = Number(req.params.id);
      // actor user id comes from JWT (requireAuth attaches req.user)
      const actorUserId = req.user.id;

      // Optional: strict validation (since Number("abc") becomes NaN)
      if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
        const err = new Error("Invalid user id");
        err.status = 400;
        throw err;
      }

      const result = await userStatusService({ targetUserId, actorUserId, statusSlug });
      res.json(result);
    } catch (err) {
      next(err);
    }
  };
}

// ADMIN: User Password Reset
export async function resetUserPasswordController(req, res, next) {
  try {
    const targetUserId = Number(req.params.id);
    const { newPassword } = req.body;

    // (Optional) validate params early (helps before calling service)
    if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
      const err = new Error("Invalid user id");
      err.status = 400;
      throw err;
    }

    const result = await resetUserPasswordService({ targetUserId, newPassword });

    res.json(result);
  } catch (err) {
    next(err);
  }
}

// // Any logged-in user
// router.get("/me", requireAuth, (req, res) => {
//   res.json({ user: req.user });
// });

// ADMIN User Management
// router.patch("/:id/disable", requireAuth, requireRole("ADMIN"), disableUserService);
// router.patch("/:id/reset-password", requireAuth, requireRole("ADMIN"), resetUserPasswordService);

// Option 2: Replace entire role set
// router.put("/:id/roles", requireAuth, requireRole("ADMIN"), updateUserRolesService);

export default router;
